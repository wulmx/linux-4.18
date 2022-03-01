/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2010-2011,2013-2015 The Linux Foundation. All rights reserved.
 */

#ifndef __LPASS_LPAIF_REG_H__
#define __LPASS_LPAIF_REG_H__

/* LPAIF I2S */

#define LPAIF_I2SCTL_REG_ADDR(v, addr, port) \
	(v->i2sctrl_reg_base + (addr) + v->i2sctrl_reg_stride * (port))

#define LPAIF_I2SCTL_REG(v, port)	LPAIF_I2SCTL_REG_ADDR(v, 0x0, (port))

#define LPAIF_I2SCTL_LOOPBACK_DISABLE	0
#define LPAIF_I2SCTL_LOOPBACK_ENABLE	1

#define LPAIF_I2SCTL_SPKEN_DISABLE	0
#define LPAIF_I2SCTL_SPKEN_ENABLE	1

#define LPAIF_I2SCTL_MODE_NONE		0
#define LPAIF_I2SCTL_MODE_SD0		1
#define LPAIF_I2SCTL_MODE_SD1		2
#define LPAIF_I2SCTL_MODE_SD2		3
#define LPAIF_I2SCTL_MODE_SD3		4
#define LPAIF_I2SCTL_MODE_QUAD01	5
#define LPAIF_I2SCTL_MODE_QUAD23	6
#define LPAIF_I2SCTL_MODE_6CH		7
#define LPAIF_I2SCTL_MODE_8CH		8
#define LPAIF_I2SCTL_MODE_10CH		9
#define LPAIF_I2SCTL_MODE_12CH		10
#define LPAIF_I2SCTL_MODE_14CH		11
#define LPAIF_I2SCTL_MODE_16CH		12
#define LPAIF_I2SCTL_MODE_SD4		13
#define LPAIF_I2SCTL_MODE_SD5		14
#define LPAIF_I2SCTL_MODE_SD6		15
#define LPAIF_I2SCTL_MODE_SD7		16
#define LPAIF_I2SCTL_MODE_QUAD45	17
#define LPAIF_I2SCTL_MODE_QUAD47	18
#define LPAIF_I2SCTL_MODE_8CH_2		19

#define LPAIF_I2SCTL_SPKMODE(mode)	mode

#define LPAIF_I2SCTL_SPKMONO_STEREO	0
#define LPAIF_I2SCTL_SPKMONO_MONO	1

#define LPAIF_I2SCTL_MICEN_DISABLE	0
#define LPAIF_I2SCTL_MICEN_ENABLE	1

#define LPAIF_I2SCTL_MICMODE(mode)	mode

#define LPAIF_I2SCTL_MICMONO_STEREO	0
#define LPAIF_I2SCTL_MICMONO_MONO	1

#define LPAIF_I2SCTL_WSSRC_INTERNAL	0
#define LPAIF_I2SCTL_WSSRC_EXTERNAL	1

#define LPAIF_I2SCTL_BITWIDTH_16	0
#define LPAIF_I2SCTL_BITWIDTH_24	1
#define LPAIF_I2SCTL_BITWIDTH_32	2

/* LPAIF IRQ */
#define LPAIF_IRQ_REG_ADDR(v, addr, port) \
	(v->irq_reg_base + (addr) + v->irq_reg_stride * (port))

#define LPAIF_IRQ_PORT_HOST		0

#define LPAIF_IRQEN_REG(v, port)	LPAIF_IRQ_REG_ADDR(v, 0x0, (port))
#define LPAIF_IRQSTAT_REG(v, port)	LPAIF_IRQ_REG_ADDR(v, 0x4, (port))
#define LPAIF_IRQCLEAR_REG(v, port)	LPAIF_IRQ_REG_ADDR(v, 0xC, (port))

#define LPAIF_IRQ_BITSTRIDE		3

#define LPAIF_IRQ_PER(chan)		(1 << (LPAIF_IRQ_BITSTRIDE * (chan)))
#define LPAIF_IRQ_XRUN(chan)		(2 << (LPAIF_IRQ_BITSTRIDE * (chan)))
#define LPAIF_IRQ_ERR(chan)		(4 << (LPAIF_IRQ_BITSTRIDE * (chan)))

#define LPAIF_IRQ_ALL(chan)		(7 << (LPAIF_IRQ_BITSTRIDE * (chan)))

/* LPAIF DMA */

#define LPAIF_RDMA_REG_ADDR(v, addr, chan) \
	(v->rdma_reg_base + (addr) + v->rdma_reg_stride * (chan))

#define LPAIF_RDMACTL_AUDINTF(id)	(id << LPAIF_RDMACTL_AUDINTF_SHIFT)

#define LPAIF_RDMACTL_REG(v, chan)	LPAIF_RDMA_REG_ADDR(v, 0x00, (chan))
#define LPAIF_RDMABASE_REG(v, chan)	LPAIF_RDMA_REG_ADDR(v, 0x04, (chan))
#define	LPAIF_RDMABUFF_REG(v, chan)	LPAIF_RDMA_REG_ADDR(v, 0x08, (chan))
#define LPAIF_RDMACURR_REG(v, chan)	LPAIF_RDMA_REG_ADDR(v, 0x0C, (chan))
#define	LPAIF_RDMAPER_REG(v, chan)	LPAIF_RDMA_REG_ADDR(v, 0x10, (chan))
#define	LPAIF_RDMAPERCNT_REG(v, chan)	LPAIF_RDMA_REG_ADDR(v, 0x14, (chan))

#define LPAIF_WRDMA_REG_ADDR(v, addr, chan) \
	(v->wrdma_reg_base + (addr) + \
	 v->wrdma_reg_stride * (chan - v->wrdma_channel_start))

#define LPAIF_WRDMACTL_REG(v, chan)	LPAIF_WRDMA_REG_ADDR(v, 0x00, (chan))
#define LPAIF_WRDMABASE_REG(v, chan)	LPAIF_WRDMA_REG_ADDR(v, 0x04, (chan))
#define	LPAIF_WRDMABUFF_REG(v, chan)	LPAIF_WRDMA_REG_ADDR(v, 0x08, (chan))
#define LPAIF_WRDMACURR_REG(v, chan)	LPAIF_WRDMA_REG_ADDR(v, 0x0C, (chan))
#define	LPAIF_WRDMAPER_REG(v, chan)	LPAIF_WRDMA_REG_ADDR(v, 0x10, (chan))
#define	LPAIF_WRDMAPERCNT_REG(v, chan)	LPAIF_WRDMA_REG_ADDR(v, 0x14, (chan))

#define __LPAIF_DMA_REG(v, chan, dir, reg)  \
	(dir ==  SNDRV_PCM_STREAM_PLAYBACK) ? \
		LPAIF_RDMA##reg##_REG(v, chan) : \
		LPAIF_WRDMA##reg##_REG(v, chan)

#define LPAIF_DMACTL_REG(v, chan, dir) __LPAIF_DMA_REG(v, chan, dir, CTL)
#define LPAIF_DMABASE_REG(v, chan, dir) __LPAIF_DMA_REG(v, chan, dir, BASE)
#define	LPAIF_DMABUFF_REG(v, chan, dir) __LPAIF_DMA_REG(v, chan, dir, BUFF)
#define LPAIF_DMACURR_REG(v, chan, dir) __LPAIF_DMA_REG(v, chan, dir, CURR)
#define	LPAIF_DMAPER_REG(v, chan, dir) __LPAIF_DMA_REG(v, chan, dir, PER)
#define	LPAIF_DMAPERCNT_REG(v, chan, dir) __LPAIF_DMA_REG(v, chan, dir, PERCNT)

#define LPAIF_DMACTL_BURSTEN_SINGLE	0
#define LPAIF_DMACTL_BURSTEN_INCR4	1

#define LPAIF_DMACTL_WPSCNT_ONE		0
#define LPAIF_DMACTL_WPSCNT_TWO		1
#define LPAIF_DMACTL_WPSCNT_THREE	2
#define LPAIF_DMACTL_WPSCNT_FOUR	3
#define LPAIF_DMACTL_WPSCNT_SIX		5
#define LPAIF_DMACTL_WPSCNT_EIGHT	7
#define LPAIF_DMACTL_WPSCNT_TEN		9
#define LPAIF_DMACTL_WPSCNT_TWELVE	11
#define LPAIF_DMACTL_WPSCNT_FOURTEEN	13
#define LPAIF_DMACTL_WPSCNT_SIXTEEN	15

#define LPAIF_DMACTL_AUDINTF(id)	id

#define LPAIF_DMACTL_FIFOWM_1		0
#define LPAIF_DMACTL_FIFOWM_2		1
#define LPAIF_DMACTL_FIFOWM_3		2
#define LPAIF_DMACTL_FIFOWM_4		3
#define LPAIF_DMACTL_FIFOWM_5		4
#define LPAIF_DMACTL_FIFOWM_6		5
#define LPAIF_DMACTL_FIFOWM_7		6
#define LPAIF_DMACTL_FIFOWM_8		7
#define LPAIF_DMACTL_FIFOWM_9		8
#define LPAIF_DMACTL_FIFOWM_10		9
#define LPAIF_DMACTL_FIFOWM_11		10
#define LPAIF_DMACTL_FIFOWM_12		11
#define LPAIF_DMACTL_FIFOWM_13		12
#define LPAIF_DMACTL_FIFOWM_14		13
#define LPAIF_DMACTL_FIFOWM_15		14
#define LPAIF_DMACTL_FIFOWM_16		15
#define LPAIF_DMACTL_FIFOWM_17		16
#define LPAIF_DMACTL_FIFOWM_18		17
#define LPAIF_DMACTL_FIFOWM_19		18
#define LPAIF_DMACTL_FIFOWM_20		19
#define LPAIF_DMACTL_FIFOWM_21		20
#define LPAIF_DMACTL_FIFOWM_22		21
#define LPAIF_DMACTL_FIFOWM_23		22
#define LPAIF_DMACTL_FIFOWM_24		23
#define LPAIF_DMACTL_FIFOWM_25		24
#define LPAIF_DMACTL_FIFOWM_26		25
#define LPAIF_DMACTL_FIFOWM_27		26
#define LPAIF_DMACTL_FIFOWM_28		27
#define LPAIF_DMACTL_FIFOWM_29		28
#define LPAIF_DMACTL_FIFOWM_30		29
#define LPAIF_DMACTL_FIFOWM_31		30
#define LPAIF_DMACTL_FIFOWM_32		31

#define LPAIF_DMACTL_ENABLE_OFF		0
#define LPAIF_DMACTL_ENABLE_ON		1

#define LPAIF_DMACTL_DYNCLK_OFF		0
#define LPAIF_DMACTL_DYNCLK_ON		1

#endif /* __LPASS_LPAIF_REG_H__ */