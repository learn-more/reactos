/*
 * PROJECT:     ReactOS Intel PRO/1000 Driver
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Interrupt handlers
 * COPYRIGHT:   Copyright 2013 Cameron Gutman (cameron.gutman@reactos.org)
 *              Copyright 2018 Mark Jansen (mark.jansen@reactos.org)
 */

#include "nic.h"

#include <debug.h>

VOID
NTAPI
MiniportISR(
    OUT PBOOLEAN InterruptRecognized,
    OUT PBOOLEAN QueueMiniportHandleInterrupt,
    IN NDIS_HANDLE MiniportAdapterContext)
{
    ULONG Value;
    PE1000_ADAPTER Adapter = (PE1000_ADAPTER)MiniportAdapterContext;

    Value = NICInterruptRecognized(Adapter, InterruptRecognized);
    InterlockedOr(&Adapter->InterruptPending, Value);

    if (!(*InterruptRecognized))
    {
        /* This is not ours. */
        *QueueMiniportHandleInterrupt = FALSE;
        return;
    }

    /* Mark the events pending service */
    *QueueMiniportHandleInterrupt = TRUE;
}

VOID
NTAPI
MiniportHandleInterrupt(
    IN NDIS_HANDLE MiniportAdapterContext)
{
    ULONG Value;
    PE1000_ADAPTER Adapter = (PE1000_ADAPTER)MiniportAdapterContext;
    volatile PE1000_TRANSMIT_DESCRIPTOR TransmitDescriptor;

    //NDIS_DbgPrint(MAX_TRACE, ("Called.\n"));

    Value = InterlockedExchange(&Adapter->InterruptPending, 0);

    NdisDprAcquireSpinLock(&Adapter->AdapterLock);

    if (Value & E1000_IMS_LSC)
    {
        ULONG Status;

        Value &= ~E1000_IMS_LSC;
        NDIS_DbgPrint(MIN_TRACE, ("Link status changed!.\n"));

        NICUpdateLinkStatus(Adapter);

        Status = Adapter->MediaState == NdisMediaStateConnected ? NDIS_STATUS_MEDIA_CONNECT : NDIS_STATUS_MEDIA_DISCONNECT;

        NdisDprReleaseSpinLock(&Adapter->AdapterLock);
        NdisMIndicateStatus(Adapter->AdapterHandle, Status, NULL, 0);
        NdisMIndicateStatusComplete(Adapter->AdapterHandle);

        NdisDprAcquireSpinLock(&Adapter->AdapterLock);
    }

    if (Value & (E1000_IMS_RXDMT0 | E1000_IMS_RXT0))
    {
        volatile PE1000_RECEIVE_DESCRIPTOR ReceiveDescriptor;
        PETH_HEADER EthHeader;
        ULONG BufferOffset;

        /* Clear out these interrupts */
        Value &= ~(E1000_IMS_RXDMT0 | E1000_IMS_RXT0);

        while (TRUE)
        {
            BufferOffset = Adapter->CurrentRxDesc * Adapter->ReceiveBufferEntrySize;
            ReceiveDescriptor = Adapter->ReceiveDescriptors + Adapter->CurrentRxDesc;

            if (!(ReceiveDescriptor->Status & E1000_RDESC_STATUS_DD))
            {
                /* Not received yet */
                break;
            }

            if (ReceiveDescriptor->Status != (E1000_RDESC_STATUS_EOP | E1000_RDESC_STATUS_DD))
            {
                __debugbreak();
            }

            if (ReceiveDescriptor->Length != 0)
            {
                EthHeader = (PETH_HEADER)(Adapter->ReceiveBuffer + BufferOffset);

                NdisDprReleaseSpinLock(&Adapter->AdapterLock);

                NdisMEthIndicateReceive(Adapter->AdapterHandle,
                                        NULL,
                                        (PCHAR)EthHeader,
                                        sizeof(ETH_HEADER),
                                        (PCHAR)(EthHeader + 1),
                                        ReceiveDescriptor->Length - sizeof(ETH_HEADER),
                                        ReceiveDescriptor->Length - sizeof(ETH_HEADER));

#if 0
                NDIS_DbgPrint(MAX_TRACE, ("Rx: %u, (%u.%u.%u.%u:%u to %u.%u.%u.%u:%u, type: %u)\n",
                                          ReceiveDescriptor->Length,
                                          EthHeader->Source[0], EthHeader->Source[1], EthHeader->Source[2], EthHeader->Source[3], EthHeader->Source[4], EthHeader->Source[5],
                                          EthHeader->Destination[0], EthHeader->Destination[1], EthHeader->Destination[2], EthHeader->Destination[3], EthHeader->Destination[4], EthHeader->Destination[5],
                                          EthHeader->PayloadType));
#endif

                if (ReceiveDescriptor->Status & E1000_RDESC_STATUS_EOP)
                {
                    NdisMEthIndicateReceiveComplete(Adapter->AdapterHandle);
                    //NDIS_DbgPrint(MAX_TRACE, ("Rx: Complete\n", ReceiveDescriptor->Length, sizeof(ETH_HEADER)));
                }
                else
                {
                    __debugbreak();
                }
                NdisDprAcquireSpinLock(&Adapter->AdapterLock);
            }

            /* Restore the descriptor Address, incase we received a NULL descriptor */
            ReceiveDescriptor->Address = Adapter->ReceiveBufferPa.QuadPart + BufferOffset;
            /* Give the descriptor back */
            ReceiveDescriptor->Status = 0;
            E1000WriteUlong(Adapter, E1000_REG_RDT, Adapter->CurrentRxDesc);
            Adapter->CurrentRxDesc = (Adapter->CurrentRxDesc + 1) % NUM_RECEIVE_DESCRIPTORS;
        }

        //NDIS_DbgPrint(MAX_TRACE, ("Rx: Done\n", ReceiveDescriptor->Length, sizeof(ETH_HEADER)));
    }
    NdisDprReleaseSpinLock(&Adapter->AdapterLock);



    if (TRUE /*Value & E1000_IMS_TXDW*/)
    {
        NdisDprAcquireSpinLock(&Adapter->SendLock);

        while (Adapter->TxFull || Adapter->LastTxDesc != Adapter->CurrentTxDesc)
        {
            TransmitDescriptor = Adapter->TransmitDescriptors + Adapter->LastTxDesc;

            if (!(TransmitDescriptor->Status & E1000_TDESC_STATUS_DD))
            {
                /* Not processed yet */
                break;
            }

            if (Adapter->TransmitPackets[Adapter->LastTxDesc])
            {
                NdisDprReleaseSpinLock(&Adapter->SendLock);
                NdisMSendComplete(Adapter->AdapterHandle, Adapter->TransmitPackets[Adapter->LastTxDesc], NDIS_STATUS_SUCCESS);
                NdisDprAcquireSpinLock(&Adapter->SendLock);
                Adapter->TransmitPackets[Adapter->LastTxDesc] = NULL;
            }

            Adapter->LastTxDesc = (Adapter->LastTxDesc + 1) % NUM_TRANSMIT_DESCRIPTORS;
            Value &= ~E1000_IMS_TXDW;
            Adapter->TxFull = FALSE;
            //NDIS_DbgPrint(MAX_TRACE, ("CurrentTxDesc:%u, LastTxDesc:%u\n", Adapter->CurrentTxDesc, Adapter->LastTxDesc));
        }

        //NDIS_DbgPrint(MAX_TRACE, ("Tx Done\n"));

        NdisDprReleaseSpinLock(&Adapter->SendLock);
    }

    ASSERT(Value == 0);
}
