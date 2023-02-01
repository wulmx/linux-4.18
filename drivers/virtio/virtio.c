#include <linux/virtio.h>
#include <linux/spinlock.h>
#include <linux/virtio_config.h>
#include <linux/module.h>
#include <linux/virtio_ring.h>
#include <linux/idr.h>
#include <uapi/linux/virtio_ids.h>

/* Unique numbering for virtio devices. */
static DEFINE_IDA(virtio_index_ida);

static ssize_t device_show(struct device *_d,
			   struct device_attribute *attr, char *buf)
{
	struct virtio_device *dev = dev_to_virtio(_d);
	return sprintf(buf, "0x%04x\n", dev->id.device);
}
static DEVICE_ATTR_RO(device);

static ssize_t vendor_show(struct device *_d,
			   struct device_attribute *attr, char *buf)
{
	struct virtio_device *dev = dev_to_virtio(_d);
	return sprintf(buf, "0x%04x\n", dev->id.vendor);
}
static DEVICE_ATTR_RO(vendor);

static ssize_t vqs_data_show(struct device *_d,
				struct device_attribute *attr, char *buf)
{
	return get_vqs_data(_d, buf);
}
static DEVICE_ATTR_RO(vqs_data);

static ssize_t status_show(struct device *_d,
			   struct device_attribute *attr, char *buf)
{
	struct virtio_device *dev = dev_to_virtio(_d);
	return sprintf(buf, "0x%08x\n", dev->config->get_status(dev));
}
static DEVICE_ATTR_RO(status);

static ssize_t modalias_show(struct device *_d,
			     struct device_attribute *attr, char *buf)
{
	struct virtio_device *dev = dev_to_virtio(_d);
	return sprintf(buf, "virtio:d%08Xv%08X\n",
		       dev->id.device, dev->id.vendor);
}
static DEVICE_ATTR_RO(modalias);

static ssize_t features_show(struct device *_d,
			     struct device_attribute *attr, char *buf)
{
	struct virtio_device *dev = dev_to_virtio(_d);
	unsigned int i;
	ssize_t len = 0;

	/* We actually represent this as a bitstring, as it could be
	 * arbitrary length in future. */
	for (i = 0; i < sizeof(dev->features)*8; i++)
		len += sprintf(buf+len, "%c",
			       __virtio_test_bit(dev, i) ? '1' : '0');
	len += sprintf(buf+len, "\n");
	return len;
}
static DEVICE_ATTR_RO(features);

static struct attribute *virtio_dev_attrs[] = {
	&dev_attr_device.attr,
	&dev_attr_vendor.attr,
	&dev_attr_status.attr,
	&dev_attr_modalias.attr,
	&dev_attr_features.attr,
	&dev_attr_vqs_data.attr,
	NULL,
};
ATTRIBUTE_GROUPS(virtio_dev);

static inline int virtio_id_match(const struct virtio_device *dev,
				  const struct virtio_device_id *id)
{
	if (id->device != dev->id.device && id->device != VIRTIO_DEV_ANY_ID)
		return 0;

	return id->vendor == VIRTIO_DEV_ANY_ID || id->vendor == dev->id.vendor;
}

/* This looks through all the IDs a driver claims to support.  If any of them
 * match, we return 1 and the kernel will call virtio_dev_probe(). */
static int virtio_dev_match(struct device *_dv, struct device_driver *_dr)
{
	unsigned int i;
	struct virtio_device *dev = dev_to_virtio(_dv);
	const struct virtio_device_id *ids;

	ids = drv_to_virtio(_dr)->id_table;
	for (i = 0; ids[i].device; i++)//match device id
		if (virtio_id_match(dev, &ids[i]))
			return 1;
	return 0;
}

static int virtio_uevent(struct device *_dv, struct kobj_uevent_env *env)
{
	struct virtio_device *dev = dev_to_virtio(_dv);

	return add_uevent_var(env, "MODALIAS=virtio:d%08Xv%08X",
			      dev->id.device, dev->id.vendor);
}

void virtio_check_driver_offered_feature(const struct virtio_device *vdev,
					 unsigned int fbit)
{
	unsigned int i;
	struct virtio_driver *drv = drv_to_virtio(vdev->dev.driver);

	for (i = 0; i < drv->feature_table_size; i++)
		if (drv->feature_table[i] == fbit)
			return;

	if (drv->feature_table_legacy) {
		for (i = 0; i < drv->feature_table_size_legacy; i++)
			if (drv->feature_table_legacy[i] == fbit)
				return;
	}

	BUG();
}
EXPORT_SYMBOL_GPL(virtio_check_driver_offered_feature);

static void __virtio_config_changed(struct virtio_device *dev)
{
	struct virtio_driver *drv = drv_to_virtio(dev->dev.driver);

	if (!dev->config_enabled)
		dev->config_change_pending = true;
	else if (drv && drv->config_changed)
		drv->config_changed(dev);
}

void virtio_config_changed(struct virtio_device *dev)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->config_lock, flags);
	__virtio_config_changed(dev);
	spin_unlock_irqrestore(&dev->config_lock, flags);
}
EXPORT_SYMBOL_GPL(virtio_config_changed);

void virtio_config_disable(struct virtio_device *dev)
{
	spin_lock_irq(&dev->config_lock);
	dev->config_enabled = false;
	spin_unlock_irq(&dev->config_lock);
}
EXPORT_SYMBOL_GPL(virtio_config_disable);

void virtio_config_enable(struct virtio_device *dev)
{
	spin_lock_irq(&dev->config_lock);
	dev->config_enabled = true;
	if (dev->config_change_pending)
		__virtio_config_changed(dev);
	dev->config_change_pending = false;
	spin_unlock_irq(&dev->config_lock);
}
EXPORT_SYMBOL_GPL(virtio_config_enable);

void virtio_add_status(struct virtio_device *dev, unsigned int status)
{
	might_sleep();
	// ->vp_set_status ,写pci配置空间的io地址
	dev->config->set_status(dev, dev->config->get_status(dev) | status);
}
EXPORT_SYMBOL_GPL(virtio_add_status);

int virtio_finalize_features(struct virtio_device *dev)
{
	int ret = dev->config->finalize_features(dev);//callback vp_finalize_features
	unsigned status;

	might_sleep();
	if (ret)
		return ret;

	if (!virtio_has_feature(dev, VIRTIO_F_VERSION_1))//没有1.0的feature
		return 0;

	virtio_add_status(dev, VIRTIO_CONFIG_S_FEATURES_OK);
	status = dev->config->get_status(dev);
	if (!(status & VIRTIO_CONFIG_S_FEATURES_OK)) {//读取寄存器状态无VIRTIO_CONFIG_S_FEATURES_OK
		dev_err(&dev->dev, "virtio: device refuses features: %x\n",
			status);
		return -ENODEV;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(virtio_finalize_features);

static int virtio_dev_probe(struct device *_d)
{
	int err, i;
	struct virtio_device *dev = dev_to_virtio(_d);
	struct virtio_driver *drv = drv_to_virtio(dev->dev.driver);
	u64 device_features;
	u64 driver_features;
	u64 driver_features_legacy;

	/* We have a driver! */
	virtio_add_status(dev, VIRTIO_CONFIG_S_DRIVER);//置位状态，知道是什么驱动

	/* Figure out what features the device supports. 
	 * 回调函数vp_get_features->vp_modern_get_features
	 * vp_modern_get_features 中会和后端设备协商feature
	 */
	device_features = dev->config->get_features(dev);

	/* Figure out what features the driver supports. */
	driver_features = 0;
	for (i = 0; i < drv->feature_table_size; i++) {
		unsigned int f = drv->feature_table[i];
		BUG_ON(f >= 64);
		driver_features |= (1ULL << f);
	}

	/* Some drivers have a separate feature table for virtio v1.0 */
	if (drv->feature_table_legacy) {
		driver_features_legacy = 0;
		for (i = 0; i < drv->feature_table_size_legacy; i++) {
			unsigned int f = drv->feature_table_legacy[i];
			BUG_ON(f >= 64);
			driver_features_legacy |= (1ULL << f);
		}
	} else {
		driver_features_legacy = driver_features;
	}

	if (device_features & (1ULL << VIRTIO_F_VERSION_1))
		dev->features = driver_features & device_features;
	else
		dev->features = driver_features_legacy & device_features;

	/* Transport features always preserved to pass to finalize_features. */
	for (i = VIRTIO_TRANSPORT_F_START; i < VIRTIO_TRANSPORT_F_END; i++)
		if (device_features & (1ULL << i))
			__virtio_set_bit(dev, i);

	if (drv->validate) {
		err = drv->validate(dev);
		if (err)
			goto err;
	}
	// 协商结果，成功会置位VIRTIO_CONFIG_S_FEATURES_OK，表示前后端协商成功
	err = virtio_finalize_features(dev);
	if (err)
		goto err;

	err = drv->probe(dev); //virtio_drive回调函数 virtnet_probe 或者 virtblk_probe
	if (err)
		goto err;

	/* If probe didn't do it, mark device DRIVER_OK ourselves. */
	if (!(dev->config->get_status(dev) & VIRTIO_CONFIG_S_DRIVER_OK))
		virtio_device_ready(dev);

	if (drv->scan)
		drv->scan(dev);

	virtio_config_enable(dev);

	return 0;
err:
	virtio_add_status(dev, VIRTIO_CONFIG_S_FAILED);
	return err;

}

static int virtio_dev_remove(struct device *_d)
{
	struct virtio_device *dev = dev_to_virtio(_d);
	struct virtio_driver *drv = drv_to_virtio(dev->dev.driver);

	virtio_config_disable(dev);

	drv->remove(dev);

	/* Driver should have reset device. */
	/*
	[Tue Sep 13 02:47:01 2022] WARNING: CPU: 28 PID: 696 at drivers/virtio/virtio.c:277 virtio_dev_remove+0x76/0x80
	[Tue Sep 13 02:47:01 2022] Modules linked in: xt_CHECKSUM ipt_MASQUERADE xt_conntrack ipt_REJECT nf_reject_ipv4 nft_compat nft_counter nft_chain_nat nf_nat nf_conntrack
	nf_defrag_ipv6 nf_defrag_ipv4 nf_tables nfnetlink tun bridge stp llc sunrpc vfat fat ext4 mbcache jbd2 intel_rapl_msr iTCO_wdt iTCO_vendor_support intel_rapl_common is
	st_if_common skx_edac nfit libnvdimm x86_pkg_temp_thermal coretemp kvm_intel kvm irqbypass crct10dif_pclmul crc32_pclmul ghash_clmulni_intel rapl ipmi_ssif intel_cstate
	virtio_net net_failover intel_uncore failover joydev pcspkr virtio_blk mei_me mei i2c_i801 ioatdma lpc_ich wmi acpi_ipmi ipmi_si ipmi_devintf ipmi_msghandler acpi_powe
	r_meter ip_tables xfs libcrc32c sd_mod sg ast drm_vram_helper drm_kms_helper syscopyarea nvme sysfillrect sysimgblt fb_sys_fops drm_ttm_helper nvme_core ttm crc32c_inte
	l ahci t10_pi libahci drm libata igb dca i2c_algo_bit dm_mirror dm_region_hash dm_log dm_mod fuse
	[Tue Sep 13 02:47:01 2022] CPU: 28 PID: 696 Comm: irq/36-pciehp Kdump: loaded Not tainted 4.18.0-30501.10.2.el8.x86_64 #1
	[Tue Sep 13 02:47:01 2022] Hardware name: Inspur NF5280M5/YZMB-00882-104, BIOS 4.1.19 06/16/2021
	[Tue Sep 13 02:47:01 2022] RIP: 0010:virtio_dev_remove+0x76/0x80
	[Tue Sep 13 02:47:01 2022] Code: d8 03 00 00 4c 89 e7 48 8b 40 18 e8 b4 1a 69 00 84 c0 75 16 4c 89 e7 be 01 00 00 00 e8 53 ff ff ff 31 c0 5b 5d 41 5c 41 5d c3 <0f> 0b e
	b e6 66 0f 1f 44 00 00 0f 1f 44 00 00 48 89 f0 8b 8f d4 03
	[Tue Sep 13 02:47:01 2022] RSP: 0018:ffffabf687a33c98 EFLAGS: 00010286
	[Tue Sep 13 02:47:01 2022] RAX: 00000000000000ff RBX: ffff9db546b03810 RCX: 00000000820001ff
	[Tue Sep 13 02:47:01 2022] RDX: 0000000082000200 RSI: 00000000820001ff RDI: ffffabf681c51012
	[Tue Sep 13 02:47:01 2022] RBP: ffff9db546b03808 R08: 0000000000000001 R09: ffffffff87f6f901
	[Tue Sep 13 02:47:01 2022] R10: ffff9db5467fb080 R11: 0000000000000001 R12: ffff9db546b03800
	[Tue Sep 13 02:47:01 2022] R13: ffffffffc0f3f300 R14: ffff9db727796ea4 R15: ffff9db51fb03d80
	[Tue Sep 13 02:47:01 2022] FS:  0000000000000000(0000) GS:ffff9db737600000(0000) knlGS:0000000000000000
	[Tue Sep 13 02:47:01 2022] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
	[Tue Sep 13 02:47:01 2022] CR2: 000055ed4aa43dc0 CR3: 00000002f7010002 CR4: 00000000007706e0
	[Tue Sep 13 02:47:01 2022] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
	[Tue Sep 13 02:47:01 2022] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
	[Tue Sep 13 02:47:01 2022] PKRU: 55555554
	[Tue Sep 13 02:47:01 2022] Call Trace:
	[Tue Sep 13 02:47:01 2022]  device_release_driver_internal+0x103/0x1f0
	[Tue Sep 13 02:47:01 2022]  bus_remove_device+0xf7/0x170
	[Tue Sep 13 02:47:01 2022]  device_del+0x181/0x410
	[Tue Sep 13 02:47:01 2022]  device_unregister+0x16/0x60
	[Tue Sep 13 02:47:01 2022]  unregister_virtio_device+0x11/0x20
	[Tue Sep 13 02:47:01 2022]  virtio_pci_remove+0x2f/0x60
	[Tue Sep 13 02:47:01 2022]  pci_device_remove+0x3b/0xc0
	[Tue Sep 13 02:47:01 2022]  device_release_driver_internal+0x103/0x1f0
	[Tue Sep 13 02:47:01 2022]  pci_stop_bus_device+0x69/0x90
	[Tue Sep 13 02:47:01 2022]  pci_stop_and_remove_bus_device+0xe/0x20
	[Tue Sep 13 02:47:01 2022]  pciehp_unconfigure_device+0x7c/0x130
	[Tue Sep 13 02:47:01 2022]  pciehp_disable_slot+0x6b/0x130
	[Tue Sep 13 02:47:01 2022]  pciehp_handle_disable_request+0x3b/0x60
	[Tue Sep 13 02:47:01 2022]  pciehp_ist+0x193/0x1b0
	[Tue Sep 13 02:47:01 2022]  ? irq_finalize_oneshot.part.47+0xf0/0xf0
	[Tue Sep 13 02:47:01 2022]  irq_thread_fn+0x1f/0x50
	[Tue Sep 13 02:47:01 2022]  irq_thread+0xe7/0x170
	 */
	WARN_ON_ONCE(dev->config->get_status(dev));//如果vp_get_status返回1，则告警

	/* Acknowledge the device's existence again. */
	virtio_add_status(dev, VIRTIO_CONFIG_S_ACKNOWLEDGE);
	return 0;
}

static struct bus_type virtio_bus = {
	.name  = "virtio",
	.match = virtio_dev_match,
	.dev_groups = virtio_dev_groups,
	.uevent = virtio_uevent,
	.probe = virtio_dev_probe,
	.remove = virtio_dev_remove,
};

int register_virtio_driver(struct virtio_driver *driver)
{
	/* Catch this early. */
	BUG_ON(driver->feature_table_size && !driver->feature_table);
	driver->driver.bus = &virtio_bus;// 将virtio_blk或者net驱动的总线指向virtio
	return driver_register(&driver->driver);//注册驱动
}
EXPORT_SYMBOL_GPL(register_virtio_driver);

void unregister_virtio_driver(struct virtio_driver *driver)
{
	driver_unregister(&driver->driver);
}
EXPORT_SYMBOL_GPL(unregister_virtio_driver);

/**
 * register_virtio_device - register virtio device
 * @dev        : virtio device to be registered
 *
 * On error, the caller must call put_device on &@dev->dev (and not kfree),
 * as another code path may have obtained a reference to @dev.
 *
 * Returns: 0 on suceess, -error on failure
 */
int register_virtio_device(struct virtio_device *dev)
{
	int err;

	dev->dev.bus = &virtio_bus; //设置virtio  bus
	device_initialize(&dev->dev);//会调用virtio_dev_probe

	/* Assign a unique device index and hence name. */
	err = ida_simple_get(&virtio_index_ida, 0, 0, GFP_KERNEL);
	if (err < 0)
		goto out;

	dev->index = err;
	dev_set_name(&dev->dev, "virtio%u", dev->index);//设置virtio dev name

	spin_lock_init(&dev->config_lock);
	dev->config_enabled = false;
	dev->config_change_pending = false;

	/* We always start by resetting the device, in case a previous
	 * driver messed it up.  This also tests that code path a little. */
	dev->config->reset(dev);

	/* Acknowledge that we've seen the device. */
	virtio_add_status(dev, VIRTIO_CONFIG_S_ACKNOWLEDGE);//通知后端已发现此virtio设备 

	INIT_LIST_HEAD(&dev->vqs);

	/*
	 * device_add() causes the bus infrastructure to look for a matching
	 * driver.
	 */
	err = device_add(&dev->dev);
	if (err)
		ida_simple_remove(&virtio_index_ida, dev->index);
out:
	if (err)
		virtio_add_status(dev, VIRTIO_CONFIG_S_FAILED);
	return err;
}
EXPORT_SYMBOL_GPL(register_virtio_device);

bool is_virtio_device(struct device *dev)
{
	return dev->bus == &virtio_bus;
}
EXPORT_SYMBOL_GPL(is_virtio_device);

void unregister_virtio_device(struct virtio_device *dev)
{
	int index = dev->index; /* save for after device release */

	device_unregister(&dev->dev);
	ida_simple_remove(&virtio_index_ida, index);
}
EXPORT_SYMBOL_GPL(unregister_virtio_device);

#ifdef CONFIG_PM_SLEEP
int virtio_device_freeze(struct virtio_device *dev)
{
	struct virtio_driver *drv = drv_to_virtio(dev->dev.driver);

	virtio_config_disable(dev);

	dev->failed = dev->config->get_status(dev) & VIRTIO_CONFIG_S_FAILED;

	if (drv && drv->freeze)
		return drv->freeze(dev);

	return 0;
}
EXPORT_SYMBOL_GPL(virtio_device_freeze);

int virtio_device_restore(struct virtio_device *dev)
{
	struct virtio_driver *drv = drv_to_virtio(dev->dev.driver);
	int ret;

	/* We always start by resetting the device, in case a previous
	 * driver messed it up. */
	dev->config->reset(dev);

	/* Acknowledge that we've seen the device. */
	virtio_add_status(dev, VIRTIO_CONFIG_S_ACKNOWLEDGE);

	/* Maybe driver failed before freeze.
	 * Restore the failed status, for debugging. */
	if (dev->failed)
		virtio_add_status(dev, VIRTIO_CONFIG_S_FAILED);

	if (!drv)
		return 0;

	/* We have a driver! */
	virtio_add_status(dev, VIRTIO_CONFIG_S_DRIVER);

	ret = virtio_finalize_features(dev);
	if (ret)
		goto err;

	if (drv->restore) {
		ret = drv->restore(dev);
		if (ret)
			goto err;
	}

	/* Finally, tell the device we're all set */
	virtio_add_status(dev, VIRTIO_CONFIG_S_DRIVER_OK);

	virtio_config_enable(dev);

	return 0;

err:
	virtio_add_status(dev, VIRTIO_CONFIG_S_FAILED);
	return ret;
}
EXPORT_SYMBOL_GPL(virtio_device_restore);
#endif

static int virtio_init(void)
{
	if (bus_register(&virtio_bus) != 0)//注册virtio_bus总线，会生成/sys/bus/virtio/并创建divice和dirver目录
		panic("virtio bus registration failed");
	return 0;
}

static void __exit virtio_exit(void)
{
	bus_unregister(&virtio_bus);
	ida_destroy(&virtio_index_ida);
}
core_initcall(virtio_init);
module_exit(virtio_exit);

MODULE_LICENSE("GPL");
