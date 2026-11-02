#if defined(BLUTTER_SHOREBIRD_3C9C) || defined(HAS_INSTRUCTIONS_TABLE_RODATA)
constexpr bool previousTableSupport = true;
#else
constexpr bool previousTableSupport = false;
#endif

#include "RuntimeFeatures.h"

#ifdef HAS_INSTRUCTIONS_TABLE_RODATA
constexpr bool tableSupport = true;
#else
constexpr bool tableSupport = false;
#endif

static_assert(tableSupport == previousTableSupport, "Table support differs from the previous rule");
static_assert(tableSupport == EXPECT_TABLE_SUPPORT, "Unexpected table support");

int main()
{
	return 0;
}
