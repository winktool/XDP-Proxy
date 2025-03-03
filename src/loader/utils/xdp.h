#pragma once

#include <xdp/libxdp.h>

#include  <common/all.h>

#include <loader/utils/config.h>
#include <loader/utils/helpers.h>

#define XDP_OBJ_PATH "/etc/xdpfwd/xdp_prog.o"
#define XDP_MAP_PIN_DIR "/sys/fs/bpf/xdpfwd"

int get_map_fd(struct xdp_program *prog, const char *map_name);
void set_libbpf_log_mode(int silent);

struct xdp_program *load_bpf_obj(const char *file_name);
struct bpf_object* get_bpf_obj(struct xdp_program* prog);

int attach_xdp(struct xdp_program *prog, char** mode, int ifidx, int detach, int force_skb, int force_offload);

int delete_fwd_rule(int map_fwd_rules, fwd_rule_cfg_t* rule);
void delete_fwd_rules(int map_fwd_rules, config__t *cfg);

int update_fwd_rule(int map_fwd_rules, fwd_rule_cfg_t* rule_cfg);
void update_fwd_rules(int map_fwd_rules, config__t *cfg);

int pin_map(struct bpf_object* obj, const char* pin_dir, const char* map_name);
int unpin_map(struct bpf_object* obj, const char* pin_dir, const char* map_name);
int get_map_pin_fd(const char* pin_dir, const char* map_name);