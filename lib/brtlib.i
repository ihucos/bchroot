%module brtlib
%{
#include "brtlib.h"
%}

%ignore brt_whitelist_env;
%ignore brt_path;
%ignore brt_whitelist_envs_from_env;

%rename("%(strip:[brt_])s") "";

%include "brtlib.h";

