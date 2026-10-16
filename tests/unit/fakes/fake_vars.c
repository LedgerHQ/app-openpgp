#include "os.h"
#include "cx.h"
#include "ux.h"
#include "gpg_types.h"

// Same globals as gpg_vars.c, with the persistent state writable by nvm_write()
gpg_v_state_t G_gpg_vstate;

gpg_nv_state_t N_state_pic;
