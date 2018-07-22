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
    ULONG InterruptPending;
    PE1000_ADAPTER Adapter = (PE1000_ADAPTER)MiniportAdapterContext;
    volatile PE1000_TRANSMIT_DESCRIPTOR TransmitDescriptor;

    //NDIS_DbgPrint(MAX_TRACE, ("Called.\n"));

    InterruptPending = InterlockedExchange(&Adapter->InterruptPending, 0);

    E1000_LOCK_ADAPTER(Adapter);

    if (InterruptPending & E1000_IMS_LSC)
    {
        ULONG Status;

        InterruptPending &= ~E1000_IMS_LSC;
        NDIS_DbgPrint(MAX_TRACE, ("Link status changed!.\n"));

        NICUpdateLinkStatus(Adapter);

        Status = Adapter->MediaState == NdisMediaStateConnected ? NDIS_STATUS_MEDIA_CONNECT : NDIS_STATUS_MEDIA_DISCONNECT;

        E1000_UNLOCK_ADAPTER(Adapter);
        NdisMIndicateStatus(Adapter->AdapterHandle, Status, NULL, 0);
        NdisMIndicateStatusComplete(Adapter->AdapterHandle);

        E1000_LOCK_ADAPTER(Adapter);
    }

    if (InterruptPending & (E1000_IMS_RXDMT0 | E1000_IMS_RXT0))
    {
        volatile PE1000_RECEIVE_DESCRIPTOR ReceiveDescriptor;
        PETH_HEADER EthHeader;
        ULONG BufferOffset;
        BOOLEAN bGotAny = FALSE;
        //ULONG CurrentRxDesc;
        ULONG RxDescHead, RxDescTail, CurrRxDesc;

        /* Clear out these interrupts */
        InterruptPending &= ~(E1000_IMS_RXDMT0 | E1000_IMS_RXT0);

        E1000ReadUlong(Adapter, E1000_REG_RDH, &RxDescHead);
        E1000ReadUlong(Adapter, E1000_REG_RDT, &RxDescTail);

        while (((RxDescTail + 1)  % NUM_RECEIVE_DESCRIPTORS) != RxDescHead)
        {
            CurrRxDesc = (RxDescTail + 1)  % NUM_RECEIVE_DESCRIPTORS;
            //__debugbreak();
            BufferOffset = CurrRxDesc * Adapter->ReceiveBufferEntrySize;
            ReceiveDescriptor = Adapter->ReceiveDescriptors + CurrRxDesc;

            if (!(ReceiveDescriptor->Status & E1000_RDESC_STATUS_DD))
            {
                /* Not received yet */
                //if (!bGotAny)
                    __debugbreak();
                break;
            }

            if (ReceiveDescriptor->Status != (E1000_RDESC_STATUS_EOP | E1000_RDESC_STATUS_DD))
            {
                __debugbreak();
            }

            if (ReceiveDescriptor->Length != 0)
            {
                EthHeader = (PETH_HEADER)(Adapter->ReceiveBuffer + BufferOffset);

                E1000_UNLOCK_ADAPTER(Adapter);

                NdisMEthIndicateReceive(Adapter->AdapterHandle,
                                        NULL,
                                        (PCHAR)EthHeader,
                                        sizeof(ETH_HEADER),
                                        (PCHAR)(EthHeader + 1),
                                        ReceiveDescriptor->Length - sizeof(ETH_HEADER),
                                        ReceiveDescriptor->Length - sizeof(ETH_HEADER));

#if 1
                NDIS_DbgPrint(MAX_TRACE, ("Rx: %u, (%u.%u.%u.%u.%u.%u to %u.%u.%u.%u.%u.%u, type: %u)\n",
                                          ReceiveDescriptor->Length,
                                          EthHeader->Source[0], EthHeader->Source[1], EthHeader->Source[2], EthHeader->Source[3], EthHeader->Source[4], EthHeader->Source[5],
                                          EthHeader->Destination[0], EthHeader->Destination[1], EthHeader->Destination[2], EthHeader->Destination[3], EthHeader->Destination[4], EthHeader->Destination[5],
                                          EthHeader->PayloadType));
#endif

                E1000_LOCK_ADAPTER(Adapter);
            }
            else
            {
                __debugbreak();
            }

            /* Restore the descriptor Address, incase we received a NULL descriptor */
            //ReceiveDescriptor->Address = Adapter->ReceiveBufferPa.QuadPart + BufferOffset;
            /* Give the descriptor back */
            ReceiveDescriptor->Status = 0;
            bGotAny = TRUE;
            //CurrentRxDesc = Adapter->CurrentRxDesc;
            //Adapter->CurrentRxDesc = (Adapter->CurrentRxDesc + 1) % NUM_RECEIVE_DESCRIPTORS;
            //RxDescTail = (RxDescTail + 1) % NUM_RECEIVE_DESCRIPTORS;
            RxDescTail = CurrRxDesc;
        }
        if (bGotAny)
        {
            E1000WriteUlong(Adapter, E1000_REG_RDT, RxDescTail);
            NDIS_DbgPrint(MAX_TRACE, ("Rx: Done (%u)\n", RxDescTail));

            //E1000ReadUlong(Adapter, E1000_REG_RDH, &Value);
            //NDIS_DbgPrint(MAX_TRACE, ("Rx: TDT: (RDH: %u, RDT: %u)\n", Value, Adapter->CurrentRxDesc));
            NDIS_DbgPrint(MAX_TRACE, ("Rx: TDT: (RDH: %u, RDT: %u)\n", RxDescHead, RxDescTail));

            NdisMEthIndicateReceiveComplete(Adapter->AdapterHandle);
        }
        //NDIS_DbgPrint(MAX_TRACE, ("Rx: Done\n", ReceiveDescriptor->Length, sizeof(ETH_HEADER)));
    }
    E1000_UNLOCK_ADAPTER(Adapter);



    if (TRUE /*Value & E1000_IMS_TXDW*/)
    {
        PNDIS_PACKET AckPackets[40] = {0};
        ULONG NumPackets = 0, n;
        E1000_LOCK_SEND(Adapter);

        while ((Adapter->TxFull || Adapter->LastTxDesc != Adapter->CurrentTxDesc) && NumPackets < ARRAYSIZE(AckPackets))
        {
            TransmitDescriptor = Adapter->TransmitDescriptors + Adapter->LastTxDesc;

            if (!(TransmitDescriptor->Status & E1000_TDESC_STATUS_DD))
            {
                /* Not processed yet */
                if (InterruptPending & E1000_IMS_TXDW)
                {

                    __debugbreak();
                }
                break;
            }

            if (Adapter->TransmitPackets[Adapter->LastTxDesc])
            {
                AckPackets[NumPackets++] = Adapter->TransmitPackets[Adapter->LastTxDesc];
                Adapter->TransmitPackets[Adapter->LastTxDesc] = NULL;
            }

            Adapter->LastTxDesc = (Adapter->LastTxDesc + 1) % NUM_TRANSMIT_DESCRIPTORS;
            InterruptPending &= ~E1000_IMS_TXDW;
            Adapter->TxFull = FALSE;
            //NDIS_DbgPrint(MAX_TRACE, ("CurrentTxDesc:%u, LastTxDesc:%u\n", Adapter->CurrentTxDesc, Adapter->LastTxDesc));
            //break;
        }

        //NDIS_DbgPrint(MAX_TRACE, ("Tx Done\n"));

        E1000_UNLOCK_SEND(Adapter);

        if (NumPackets)
        {
            ULONG Value2;

            E1000ReadUlong(Adapter, E1000_REG_TDH, &Value);
            E1000ReadUlong(Adapter, E1000_REG_TDT, &Value2);

            NDIS_DbgPrint(MAX_TRACE, ("Tx: (TDH: %u, TDT: %u)\n", Value, Value2));
            NDIS_DbgPrint(MAX_TRACE, ("Tx: (TDH: %u, TDT: %u)\n", Adapter->CurrentTxDesc, Adapter->LastTxDesc));

            NDIS_DbgPrint(MAX_TRACE, ("Tx Done: %u packets to ack\n", NumPackets));
            for (n = 0; n < NumPackets; ++n)
            {
                NdisMSendComplete(Adapter->AdapterHandle, AckPackets[n], NDIS_STATUS_SUCCESS);
            }
        }
    }

    ASSERT(InterruptPending == 0);
}
