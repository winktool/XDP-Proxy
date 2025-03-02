#pragma once

#include <xdp/libxdp.h>

#include  <common/all.h>

#include <loader/utils/config.h>
#include <loader/utils/helpers.h>

#define XDP_OBJ_PATH "/etc/xdpfwd/xdp_prog.o"
#define XDP_MAP_PIN_DIR "/sys/fs/bpf/xdpfwd"

int FindMapFd(struct xdp_program *prog, const char *map_name);
void SetLibBPFLogMode(int silent);

struct xdp_program *LoadBpfObj(const char *file_name);
struct bpf_object* GetBpfObj(struct xdp_program* prog);

int AttachXdp(struct xdp_program *prog, char** mode, int ifidx, int detach, int force_skb, int force_offload);

int DeleteRule(int map_fwd_rules, fwd_rule_cfg_t* rule);
void DeleteRules(int map_fwd_rules, config__t *cfg);

int UpdateFwdRule(int map_fwd_rules, fwd_rule_cfg_t* rule_cfg);
void UpdateFwdRules(int map_fwd_rules, config__t *cfg);

int PinBpfMap(struct bpf_object* obj, const char* pin_dir, const char* map_name);
int UnpinBpfMap(struct bpf_object* obj, const char* pin_dir, const char* map_name);
int GetMapPinFd(const char* pin_dir, const char* map_name);