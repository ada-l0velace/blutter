#pragma once

// Direct CMake builds may receive only the SDK profile flag.
#if defined(BLUTTER_SHOREBIRD_3C9C) && !defined(HAS_INSTRUCTIONS_TABLE_RODATA)
#define HAS_INSTRUCTIONS_TABLE_RODATA
#endif
