// Import the platform-neutral test entry point into Swift.
// Do not expose the full upstream cpu.h ABI through Swift bridging.
#include "GuestSmoke.h"

#include "GuestImageProbe.h"

// iOS Touch and GameController -> DirectInput (DIK_*) Bridge
#include "NFSU2InputBridge.h"

// iOS Metal Rendering Bridge
#include "NFSU2MetalBridge.h"
