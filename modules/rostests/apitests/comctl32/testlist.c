#define STANDALONE
#include <apitest.h>

extern void func_button(void);
extern void func_imagelist(void);
extern void func_toolbar(void);

const struct test winetest_testlist[] =
{
    { "buttonv6", func_button },
    { "imagelistv6", func_imagelist },
    { "toolbarv6", func_toolbar },
    { 0, 0 }
};
