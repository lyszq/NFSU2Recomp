#if defined(NFS_FULL_RUNTIME)
// Full game builds use the strong runtime renderer and persistent session.
#include "NFSU2GameSession.h"
#include "metal.h"
#else
// The default app remains the bounded diagnostic build.
#include "GuestSmoke.h"
#include "GuestImageProbe.h"
#include "NFSU2MetalBridge.h"
#endif

// UIKit/GameController input bridge is shared by both app lanes.
#include "NFSU2InputBridge.h"
