#ifndef _UAPI_LINUX_VIRTIO_RING_H
#define _UAPI_LINUX_VIRTIO_RING_H
/* An interface for efficient virtio implementation, currently for use by KVM,
 * but hopefully others soon.  Do NOT change this since it will
 * break existing servers and clients.
 *
 * This header is BSD licensed so anyone can use the definitions to implement
 * compatible drivers/servers.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of IBM nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL IBM OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Copyright Rusty Russell IBM Corporation 2007. */
#ifndef __KERNEL__
#include <stdint.h>
#endif
#include <linux/types.h>
#include <linux/virtio_types.h>

/* This marks a buffer as continuing via the next field. */
/* VIRTQ_DESC_F_NEXT 只有在avail desc中有意义，用于支持Descriptor Chain，在used desc中没有意义；
使用方法
当驱动在一次请求中写入多个buffer元素 时，需要设置avail desc中flags 对应VIRTQ_DESC_F_NEXT位，
具体操作步骤如下：
驱动延时更新第一个desc 的flags，即desc 链中其他desc的flags全部更新完再更新第一个desc链中第一
的desc的flags，这样可以保证后面看到的是完整的desc 链表；
buffer id 包含再desc chain 的最后一个desc中；
desc chain 中每个desc 要合理正确设置VIRTQ_DESC_F_AVAIL, VIRTQ_DESC_F_USED, VIRTQ_DESC_F_WRITE ；
设备处理完当前请求desc list 所有元素只回写一个used desc，
向前跳过desc chain 所有元素在desc ring中写入used desc，驱动也能根据desc chain bufferid
算出desc chain的大小以便找到设备写入desc ring 中used desc的位置。*/
#define VRING_DESC_F_NEXT	1
/* This marks a buffer as write-only (otherwise read-only). 
 * 对于avail desc这个flag用来标记其关联的buffer是只读的还是只写的；
 * 对于used desc这个flag用来表示去关联的buffer是否有被后端（device）写入数据；
 */
#define VRING_DESC_F_WRITE	2
/* This means the buffer contains a list of buffer descriptors. 
首先driver 分配一个 indirect desc 的空间，它和普通的packed virtqueue desc中的布局是完全相同的，
对于device来说只读；
设置每一个indirect desc指向的buffer信息，和普通的packed virtqueue desc 设置相同，
包括addr(buffer),len(buffer),bufferid(buffer);
设置main  virtqueue desc 的addr(indirect desc),len(indirect desc)，bufferid 无效;
设置main virtqueue desc flags ，flags|VIRTQ_DESC_F_INDIRECT；
设置flags|VIRTQ_DESC_F_INDIRECT后，即使desc 设置了VIRTQ_DESC_F_WRITE，VIRTQ_DESC_F_WRITE对device
来说也是无效的*/
#define VRING_DESC_F_INDIRECT	4

/* 1.1 spec用来区分驱动还是设备的ring ， 即 是avail 还是 used
 * 区别于0.95 中的split ring
 * Mark a descriptor as available or used in packed ring.
 * Notice: they are defined as shifts instead of shifted values.
 */
#define VRING_PACKED_DESC_F_AVAIL	7
#define VRING_PACKED_DESC_F_USED	15

/* The Host uses this in used->flags to advise the Guest: don't kick me when
 * you add a buffer.  It's unreliable, so it's simply an optimization.  Guest
 * will still kick if it's out of buffers. */
#define VRING_USED_F_NO_NOTIFY	1
/* The Guest uses this in avail->flags to advise the Host: don't interrupt me
 * when you consume a buffer.  It's unreliable, so it's simply an
 * optimization.  */
#define VRING_AVAIL_F_NO_INTERRUPT	1

/* Enable events in packed ring. */
#define VRING_PACKED_EVENT_FLAG_ENABLE	0x0
/* Disable events in packed ring. */
#define VRING_PACKED_EVENT_FLAG_DISABLE	0x1
/*
 * Enable events for a specific descriptor in packed ring.
 * (as specified by Descriptor Ring Change Event Offset/Wrap Counter).
 * Only valid if VIRTIO_RING_F_EVENT_IDX has been negotiated.
 */
#define VRING_PACKED_EVENT_FLAG_DESC	0x2

/*
 * Wrap counter bit shift in event suppression structure
 * of packed ring.
 */
#define VRING_PACKED_EVENT_F_WRAP_CTR	15

/* We support indirect buffer descriptors */
#define VIRTIO_RING_F_INDIRECT_DESC	28

/* The Guest publishes the used index for which it expects an interrupt
 * at the end of the avail ring. Host should ignore the avail->flags field. */
/* The Host publishes the avail index for which it expects a kick
 * at the end of the used ring. Guest should ignore the used->flags field. */
/*
 * VIRTIO_RING_F_EVENT_IDX特性未被协商，设备须将used ring中的flags置为0或1（1表示通知设备不需要中断），
 * 驱动须忽略used ring中的avail_event，在驱动向available ring写描述符之后，驱动读取used ring中的flags，
 * 若flags为1则表示驱动不应发送通知（0表示驱动必须发送），若VIRTIO_RING_F_EVENT_IDX特性被协商，
 * 设备须将used ring中的flags置为0，驱动须忽略used ring中的flags，驱动读取used ring中的idx和avail_event，
 * idx不等于 avail_event时不应发送通知（ 等于表示必须发送通知）。需要驱动通知时，驱动向队列通知地址中
 * 写入16-bit索引，设备使用VIRTIO_PCI_CAP_NOTIFY_CFG能力，队列通知地址为
 * cap.offset + queue_notify_off * notify_off_multiplier，
 * 通过读取此地址的值判定是发哪个队列发包，而legacy则是驱动将16-bit索引写入到第一个io空间的virtio头
 * 的Queue Notify中；
 * 2022/12/17
 * 如果notify_off_multiplier， 为0 则会将所有notify 都发往一个队列，会造成性能影响
 * 
 */
#define VIRTIO_RING_F_EVENT_IDX		29

/* Virtio ring descriptors: 16 bytes.  These can chain together via "next". */
struct vring_desc {
	/* Address (guest-physical). */
	__virtio64 addr;
	/* Length. */
	__virtio32 len;
	/* The flags as indicated above. */
	/* This marks a buffer as continuing via the next field. */
	//#define VRING_DESC_F_NEXT	1
	/* This marks a buffer as write-only (otherwise read-only). */
	//#define VRING_DESC_F_WRITE	2
	/* This means the buffer contains a list of buffer descriptors. */
	//#define VRING_DESC_F_INDIRECT	4
	/* flag 用来描述上面3个宏定义 */
	__virtio16 flags;
	/* We chain unused descriptors via this, too */
	__virtio16 next;//记录chain中下一个desc idx
};

struct vring_avail {
	__virtio16 flags; //驱动使用这个标志告诉device 当消费一个buffer时不要中断
	/* 
	 * 记录最后一个可用的desc, avail->idx 不是desc ring的idx，而是avail->ring的idx
	 * 对后端来说对应的avail->ring[idx]表示最后一个可用的（对前端来说是下一个可用）desc chain的header idx
	 */
	__virtio16 idx;
	/*
	 * 对后端来说vring_avail->ring[vhost_virtqueue->last_avail_idx]表示首个可用的desc的idx
	 * 对后端来说vring_avail->ring[vhost_virtqueue->avail->idx]表示最后一个可用的desc的idx
	 */
	__virtio16 ring[];//
};

/* u32 is used here for ids for padding reasons. */
struct vring_used_elem {
	/* Index of start of used descriptor chain. */
	__virtio32 id;
	/* Total length of the descriptor chain which was used (written to) */
	__virtio32 len;
};

struct vring_used {
	__virtio16 flags;//告诉驱动当消费一个buffer不要中断
	__virtio16 idx;//表示使用了desc ring中的索引
	/*
	 * last_used_idx记录的也不是desc ring的idx，而是used->ring的idx，
	 * 对应used->ring[idx]记录的是上一次后端已经处理好可以给前端释放（对于guest rx来说）
	 * 的desc chain的header idx。
	 */
	struct vring_used_elem ring[];//存放desc的数据，索引数组，大小为virtqueue的num
};

struct vring {
	unsigned int num;//desc 的个数

	struct vring_desc *desc;

	struct vring_avail *avail;

	struct vring_used *used;
};

/* Alignment requirements for vring elements.
 * When using pre-virtio 1.0 layout, these fall out naturally.
 */
#define VRING_AVAIL_ALIGN_SIZE 2
#define VRING_USED_ALIGN_SIZE 4
#define VRING_DESC_ALIGN_SIZE 16

#ifndef VIRTIO_RING_NO_LEGACY

/* The standard layout for the ring is a continuous chunk of memory which looks
 * like this.  We assume num is a power of 2.
 *
 * struct vring
 * {
 *	// The actual descriptors (16 bytes each)
 *	struct vring_desc desc[num];
 *
 *	// A ring of available descriptor heads with free-running index.
 *	__virtio16 avail_flags;
 *	__virtio16 avail_idx;
 *	__virtio16 available[num];
 *	__virtio16 used_event_idx;
 *
 *	// Padding to the next align boundary.
 *	char pad[];
 *
 *	// A ring of used descriptor heads with free-running index.
 *	__virtio16 used_flags;
 *	__virtio16 used_idx;
 *	struct vring_used_elem used[num];
 *	__virtio16 avail_event_idx;
 * };
 */
/* We publish the used event index at the end of the available ring, and vice
 * versa. They are at the end for backwards compatibility. 
 * used event index 事件通知放在最后一个avail desc 中， 反之亦然是指avail event index 
 * 也是放在 used ring中的最后一个 desc中，
 */
#define vring_used_event(vr) ((vr)->avail->ring[(vr)->num])
#define vring_avail_event(vr) (*(__virtio16 *)&(vr)->used->ring[(vr)->num])

static inline void vring_init(struct vring *vr, unsigned int num, void *p,
			      unsigned long align)
{
	vr->num = num;
	vr->desc = p;
	vr->avail = p + num*sizeof(struct vring_desc);
	vr->used = (void *)(((uintptr_t)&vr->avail->ring[num] + sizeof(__virtio16)
		+ align-1) & ~(align - 1));
}

static inline unsigned vring_size(unsigned int num, unsigned long align)
{
	return ((sizeof(struct vring_desc) * num + sizeof(__virtio16) * (3 + num)
		 + align - 1) & ~(align - 1))
		+ sizeof(__virtio16) * 3 + sizeof(struct vring_used_elem) * num;
}

#endif /* VIRTIO_RING_NO_LEGACY */

/* The following is used with USED_EVENT_IDX and AVAIL_EVENT_IDX */
/* Assuming a given event_idx value from the other side, if
 * we have just incremented index from old to new_idx,
 * should we trigger an event? */
static inline int vring_need_event(__u16 event_idx, __u16 new_idx, __u16 old)
{
	/* Note: Xen has similar logic for notification hold-off
	 * in include/xen/interface/io/ring.h with req_event and req_prod
	 * corresponding to event_idx + 1 and new_idx respectively.
	 * Note also that req_event and req_prod in Xen start at 1,
	 * event indexes in virtio start at 0. */
	return (__u16)(new_idx - event_idx - 1) < (__u16)(new_idx - old);
}

struct vring_packed_desc_event {
	/* Descriptor Ring Change Event Offset/Wrap Counter. */
	__le16 off_wrap;
	/* Descriptor Ring Change Event Flags. */
	__le16 flags;
};

struct vring_packed_desc {
	/* 相对split addr和len名字和含义保持不变,
	 * 去掉了next，因为desc chain一定是相邻的，而split因为不通的ring可能是不相邻
	 */
	/* Buffer Address. */
	__le64 addr;
	/* Buffer Length. 
	 * 对于avail desc，len表示desc关联的buffer中被写入的数据长度；
	 * 对于uesd desc，当VIRTQ_DESC_F_WRITE被设置时，len表示后端（device）
	 * 写入数据的长度，当VIRTQ_DESC_F_WRITE没有被设置时，len没有意义
	 */
	__le32 len;
	/* Buffer ID. */
	__le16 id;//buffer id，注意不是desc的下标idx。
	/* The flags depending on descriptor type. */
	__le16 flags;
};

#endif /* _UAPI_LINUX_VIRTIO_RING_H */
