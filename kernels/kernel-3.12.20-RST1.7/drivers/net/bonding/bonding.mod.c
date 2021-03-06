#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

MODULE_INFO(intree, "Y");

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x9d9b625e, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x639d4628, __VMLINUX_SYMBOL_STR(register_netdevice) },
	{ 0xaf933aa5, __VMLINUX_SYMBOL_STR(dev_mc_sync_multiple) },
	{ 0x2d9cf3e, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x12da5bb2, __VMLINUX_SYMBOL_STR(__kmalloc) },
	{ 0xe9240ad5, __VMLINUX_SYMBOL_STR(rtmsg_ifinfo) },
	{ 0x68e2f221, __VMLINUX_SYMBOL_STR(_raw_spin_unlock) },
	{ 0x20ccab60, __VMLINUX_SYMBOL_STR(dev_mc_unsync) },
	{ 0x349cba85, __VMLINUX_SYMBOL_STR(strchr) },
	{ 0xb6b46a7c, __VMLINUX_SYMBOL_STR(param_ops_int) },
	{ 0xd0d8621b, __VMLINUX_SYMBOL_STR(strlen) },
	{ 0x43a53735, __VMLINUX_SYMBOL_STR(__alloc_workqueue_key) },
	{ 0xc65865f1, __VMLINUX_SYMBOL_STR(seq_open) },
	{ 0xabe06bf0, __VMLINUX_SYMBOL_STR(vlan_dev_vlan_id) },
	{ 0x79aa04a2, __VMLINUX_SYMBOL_STR(get_random_bytes) },
	{ 0x1b6314fd, __VMLINUX_SYMBOL_STR(in_aton) },
	{ 0xb14d5c4c, __VMLINUX_SYMBOL_STR(seq_puts) },
	{ 0x9cb4bd61, __VMLINUX_SYMBOL_STR(netdev_rx_handler_register) },
	{ 0xc7a4fbed, __VMLINUX_SYMBOL_STR(rtnl_lock) },
	{ 0x7a0bb012, __VMLINUX_SYMBOL_STR(vlan_uses_dev) },
	{ 0xc01cf848, __VMLINUX_SYMBOL_STR(_raw_read_lock) },
	{ 0x550e4eee, __VMLINUX_SYMBOL_STR(netif_carrier_on) },
	{ 0x29b85634, __VMLINUX_SYMBOL_STR(dst_release) },
	{ 0xa4eb4eff, __VMLINUX_SYMBOL_STR(_raw_spin_lock_bh) },
	{ 0x74d66461, __VMLINUX_SYMBOL_STR(skb_clone) },
	{ 0x62d3413d, __VMLINUX_SYMBOL_STR(dev_get_by_name) },
	{ 0xbe2f08a6, __VMLINUX_SYMBOL_STR(skb_copy) },
	{ 0x6b06fdce, __VMLINUX_SYMBOL_STR(delayed_work_timer_fn) },
	{ 0x753ffa62, __VMLINUX_SYMBOL_STR(seq_printf) },
	{ 0xd2da1048, __VMLINUX_SYMBOL_STR(register_netdevice_notifier) },
	{ 0xca8081a7, __VMLINUX_SYMBOL_STR(netif_carrier_off) },
	{ 0xc87c1f84, __VMLINUX_SYMBOL_STR(ktime_get) },
	{ 0xb85670b9, __VMLINUX_SYMBOL_STR(remove_proc_entry) },
	{ 0xf087137d, __VMLINUX_SYMBOL_STR(__dynamic_pr_debug) },
	{ 0x15e0e110, __VMLINUX_SYMBOL_STR(dev_set_allmulti) },
	{ 0x67c1ba09, __VMLINUX_SYMBOL_STR(vlan_vid_del) },
	{ 0x796c3b43, __VMLINUX_SYMBOL_STR(call_netdevice_notifiers) },
	{ 0xfa2bcf10, __VMLINUX_SYMBOL_STR(init_timer_key) },
	{ 0x4a8907de, __VMLINUX_SYMBOL_STR(cancel_delayed_work_sync) },
	{ 0xb2a476f7, __VMLINUX_SYMBOL_STR(vlan_vid_add) },
	{ 0x92687d5c, __VMLINUX_SYMBOL_STR(__netpoll_setup) },
	{ 0x627b9e89, __VMLINUX_SYMBOL_STR(vlan_vids_del_by_dev) },
	{ 0x91715312, __VMLINUX_SYMBOL_STR(sprintf) },
	{ 0x82ed080e, __VMLINUX_SYMBOL_STR(seq_read) },
	{ 0x7d11c268, __VMLINUX_SYMBOL_STR(jiffies) },
	{ 0x9d0d6206, __VMLINUX_SYMBOL_STR(unregister_netdevice_notifier) },
	{ 0xe2d5255a, __VMLINUX_SYMBOL_STR(strcmp) },
	{ 0x2db83ccc, __VMLINUX_SYMBOL_STR(vlan_vids_add_by_dev) },
	{ 0x8cbea347, __VMLINUX_SYMBOL_STR(netdev_master_upper_dev_link) },
	{ 0xab16f202, __VMLINUX_SYMBOL_STR(dev_mc_add) },
	{ 0x48ad5358, __VMLINUX_SYMBOL_STR(__netdev_alloc_skb) },
	{ 0xd63bcacf, __VMLINUX_SYMBOL_STR(__pskb_pull_tail) },
	{ 0xaf08e16c, __VMLINUX_SYMBOL_STR(netdev_change_features) },
	{ 0xe80d7215, __VMLINUX_SYMBOL_STR(netpoll_send_skb_on_dev) },
	{ 0x781d70ae, __VMLINUX_SYMBOL_STR(PDE_DATA) },
	{ 0x77d1acaa, __VMLINUX_SYMBOL_STR(netdev_has_upper_dev) },
	{ 0x5d41c87c, __VMLINUX_SYMBOL_STR(param_ops_charp) },
	{ 0x7b6f9c49, __VMLINUX_SYMBOL_STR(dev_set_mac_address) },
	{ 0xc7261b0e, __VMLINUX_SYMBOL_STR(unregister_pernet_subsys) },
	{ 0xd0cd57fa, __VMLINUX_SYMBOL_STR(proc_mkdir) },
	{ 0x9fdecc31, __VMLINUX_SYMBOL_STR(unregister_netdevice_many) },
	{ 0x11089ac7, __VMLINUX_SYMBOL_STR(_ctype) },
	{ 0x5a5a94a6, __VMLINUX_SYMBOL_STR(kstrtou8) },
	{ 0xf97456ea, __VMLINUX_SYMBOL_STR(_raw_spin_unlock_irqrestore) },
	{ 0x98f7ac0c, __VMLINUX_SYMBOL_STR(current_task) },
	{ 0x37befc70, __VMLINUX_SYMBOL_STR(jiffies_to_msecs) },
	{ 0x1726e399, __VMLINUX_SYMBOL_STR(arp_create) },
	{ 0x50eedeb8, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x5544b642, __VMLINUX_SYMBOL_STR(ethtool_op_get_link) },
	{ 0x20c55ae0, __VMLINUX_SYMBOL_STR(sscanf) },
	{ 0x5152e605, __VMLINUX_SYMBOL_STR(memcmp) },
	{ 0xa20107f, __VMLINUX_SYMBOL_STR(ns_capable) },
	{ 0xd62abc39, __VMLINUX_SYMBOL_STR(_raw_read_unlock) },
	{ 0xc917e655, __VMLINUX_SYMBOL_STR(debug_smp_processor_id) },
	{ 0xf6170ce2, __VMLINUX_SYMBOL_STR(__netpoll_free_async) },
	{ 0x62849ac7, __VMLINUX_SYMBOL_STR(dev_valid_name) },
	{ 0x7ebd34ed, __VMLINUX_SYMBOL_STR(__ethtool_get_settings) },
	{ 0x77b759ef, __VMLINUX_SYMBOL_STR(free_netdev) },
	{ 0xb6ed1e53, __VMLINUX_SYMBOL_STR(strncpy) },
	{ 0x2da418b5, __VMLINUX_SYMBOL_STR(copy_to_user) },
	{ 0xddfb296c, __VMLINUX_SYMBOL_STR(dev_mc_del) },
	{ 0x634a5317, __VMLINUX_SYMBOL_STR(netdev_upper_dev_unlink) },
	{ 0x6c2e3320, __VMLINUX_SYMBOL_STR(strncmp) },
	{ 0x73e20c1c, __VMLINUX_SYMBOL_STR(strlcpy) },
	{ 0x16305289, __VMLINUX_SYMBOL_STR(warn_slowpath_null) },
	{ 0xbc6ddc30, __VMLINUX_SYMBOL_STR(skb_push) },
	{ 0x8c03d20c, __VMLINUX_SYMBOL_STR(destroy_workqueue) },
	{ 0x3f74de7b, __VMLINUX_SYMBOL_STR(dev_close) },
	{ 0xf4f14de6, __VMLINUX_SYMBOL_STR(rtnl_trylock) },
	{ 0xc5263875, __VMLINUX_SYMBOL_STR(dev_mc_flush) },
	{ 0x2469810f, __VMLINUX_SYMBOL_STR(__rcu_read_unlock) },
	{ 0x75fff6c0, __VMLINUX_SYMBOL_STR(sysfs_remove_link) },
	{ 0x6091797f, __VMLINUX_SYMBOL_STR(synchronize_rcu) },
	{ 0x2b63ecd2, __VMLINUX_SYMBOL_STR(inet_confirm_addr) },
	{ 0x447fc369, __VMLINUX_SYMBOL_STR(init_net) },
	{ 0xeae1b54e, __VMLINUX_SYMBOL_STR(rtnl_link_unregister) },
	{ 0xc86befa6, __VMLINUX_SYMBOL_STR(dev_open) },
	{ 0x631e5250, __VMLINUX_SYMBOL_STR(sysfs_create_link) },
	{ 0x62efcac5, __VMLINUX_SYMBOL_STR(dev_uc_flush) },
	{ 0x3ff62317, __VMLINUX_SYMBOL_STR(local_bh_disable) },
	{ 0xfc54e817, __VMLINUX_SYMBOL_STR(skb_copy_expand) },
	{ 0xd908b3d, __VMLINUX_SYMBOL_STR(kmem_cache_alloc) },
	{ 0xdbab24a6, __VMLINUX_SYMBOL_STR(netdev_upper_get_next_dev_rcu) },
	{ 0x8bf826c, __VMLINUX_SYMBOL_STR(_raw_spin_unlock_bh) },
	{ 0x9963a089, __VMLINUX_SYMBOL_STR(queue_delayed_work_on) },
	{ 0xf0fdf6cb, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0x8084ca0f, __VMLINUX_SYMBOL_STR(netdev_rx_handler_unregister) },
	{ 0x76681c6f, __VMLINUX_SYMBOL_STR(skb_checksum_help) },
	{ 0x3bd1b1f6, __VMLINUX_SYMBOL_STR(msecs_to_jiffies) },
	{ 0x440c1596, __VMLINUX_SYMBOL_STR(kfree_skb) },
	{ 0xbc435770, __VMLINUX_SYMBOL_STR(dump_stack) },
	{ 0x799aca4, __VMLINUX_SYMBOL_STR(local_bh_enable) },
	{ 0x80fe95f1, __VMLINUX_SYMBOL_STR(alloc_netdev_mqs) },
	{ 0x5b917178, __VMLINUX_SYMBOL_STR(arp_xmit) },
	{ 0xa735523e, __VMLINUX_SYMBOL_STR(register_pernet_subsys) },
	{ 0x3076df46, __VMLINUX_SYMBOL_STR(pskb_expand_head) },
	{ 0x9c37fae0, __VMLINUX_SYMBOL_STR(ether_setup) },
	{ 0x4e678cd0, __VMLINUX_SYMBOL_STR(dev_uc_unsync) },
	{ 0xfd2820a3, __VMLINUX_SYMBOL_STR(__dev_get_by_name) },
	{ 0x67f7403e, __VMLINUX_SYMBOL_STR(_raw_spin_lock) },
	{ 0x21fb443e, __VMLINUX_SYMBOL_STR(_raw_spin_lock_irqsave) },
	{ 0x28508d6, __VMLINUX_SYMBOL_STR(unregister_netdevice_queue) },
	{ 0xc7a7a28d, __VMLINUX_SYMBOL_STR(ip_route_output_flow) },
	{ 0x5c3edd59, __VMLINUX_SYMBOL_STR(_raw_write_unlock_bh) },
	{ 0x476bad9a, __VMLINUX_SYMBOL_STR(proc_create_data) },
	{ 0xf96227ea, __VMLINUX_SYMBOL_STR(seq_lseek) },
	{ 0xfdee7d42, __VMLINUX_SYMBOL_STR(_raw_read_lock_bh) },
	{ 0xf37260ab, __VMLINUX_SYMBOL_STR(_raw_read_unlock_bh) },
	{ 0xcba6e90d, __VMLINUX_SYMBOL_STR(dev_set_promiscuity) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x49416e3c, __VMLINUX_SYMBOL_STR(dev_uc_sync_multiple) },
	{ 0xa46f2f1b, __VMLINUX_SYMBOL_STR(kstrtouint) },
	{ 0x485e093b, __VMLINUX_SYMBOL_STR(netdev_class_create_file) },
	{ 0x20b2bb2d, __VMLINUX_SYMBOL_STR(param_array_ops) },
	{ 0x5cfcd4d4, __VMLINUX_SYMBOL_STR(dev_trans_start) },
	{ 0xf33dfa5c, __VMLINUX_SYMBOL_STR(rtnl_link_register) },
	{ 0x32eeaded, __VMLINUX_SYMBOL_STR(_raw_write_lock_bh) },
	{ 0x69bbbd57, __VMLINUX_SYMBOL_STR(dev_uc_sync) },
	{ 0xb81960ca, __VMLINUX_SYMBOL_STR(snprintf) },
	{ 0x33cc9f00, __VMLINUX_SYMBOL_STR(seq_release) },
	{ 0x8235805b, __VMLINUX_SYMBOL_STR(memmove) },
	{ 0xcb5424db, __VMLINUX_SYMBOL_STR(consume_skb) },
	{ 0x7716dfa0, __VMLINUX_SYMBOL_STR(netdev_update_features) },
	{ 0x85670f1d, __VMLINUX_SYMBOL_STR(rtnl_is_locked) },
	{ 0x953d11eb, __VMLINUX_SYMBOL_STR(dev_queue_xmit) },
	{ 0x8d522714, __VMLINUX_SYMBOL_STR(__rcu_read_lock) },
	{ 0xc0dfb3b0, __VMLINUX_SYMBOL_STR(skb_put) },
	{ 0x33d169c9, __VMLINUX_SYMBOL_STR(_copy_from_user) },
	{ 0x8b395c6a, __VMLINUX_SYMBOL_STR(skb_copy_bits) },
	{ 0xf2808728, __VMLINUX_SYMBOL_STR(dev_mc_sync) },
	{ 0x6e720ff2, __VMLINUX_SYMBOL_STR(rtnl_unlock) },
	{ 0xc58a8cd, __VMLINUX_SYMBOL_STR(netdev_increment_features) },
	{ 0xbcc0b86a, __VMLINUX_SYMBOL_STR(dev_get_stats) },
	{ 0x1e22bc18, __VMLINUX_SYMBOL_STR(dev_set_mtu) },
	{ 0x66b1b5f, __VMLINUX_SYMBOL_STR(netdev_class_remove_file) },
	{ 0xe914e41e, __VMLINUX_SYMBOL_STR(strcpy) },
	{ 0x4cdb3178, __VMLINUX_SYMBOL_STR(ns_to_timeval) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "E74A280E71C4BE7AB93E6A6");
