/*
 * LIRC base driver
 *
 * by Artur Lipowski <alipowski@interia.pl>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/device.h>
#include <linux/file.h>
#include <linux/idr.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/wait.h>

#include "rc-core-priv.h"
#include <uapi/linux/lirc.h>

#define LOGHEAD		"lirc_dev (%s[%d]): "

static dev_t lirc_base_dev;

/* Used to keep track of allocated lirc devices */
static DEFINE_IDA(lirc_ida);

/* Only used for sysfs but defined to void otherwise */
static struct class *lirc_class;

/**
 * ir_lirc_raw_event() - Send raw IR data to lirc to be relayed to userspace
 *
 * @dev:	the struct rc_dev descriptor of the device
 * @ev:		the struct ir_raw_event descriptor of the pulse/space
 */
void ir_lirc_raw_event(struct rc_dev *dev, struct ir_raw_event ev)
{
	unsigned long flags;
	struct lirc_fh *fh;
	int sample;

	/* Packet start */
	if (ev.reset) {
		/*
		 * Userspace expects a long space event before the start of
		 * the signal to use as a sync.  This may be done with repeat
		 * packets and normal samples.  But if a reset has been sent
		 * then we assume that a long time has passed, so we send a
		 * space with the maximum time value.
		 */
		sample = LIRC_SPACE(LIRC_VALUE_MASK);
		dev_dbg(&dev->dev, "delivering reset sync space to lirc_dev\n");

	/* Carrier reports */
	} else if (ev.carrier_report) {
		sample = LIRC_FREQUENCY(ev.carrier);
		dev_dbg(&dev->dev, "carrier report (freq: %d)\n", sample);

	/* Packet end */
	} else if (ev.timeout) {
		if (dev->gap)
			return;

		dev->gap_start = ktime_get();
		dev->gap = true;
		dev->gap_duration = ev.duration;

		sample = LIRC_TIMEOUT(ev.duration / 1000);
		dev_dbg(&dev->dev, "timeout report (duration: %d)\n", sample);

	/* Normal sample */
	} else {
		if (dev->gap) {
			dev->gap_duration += ktime_to_ns(ktime_sub(ktime_get(),
							 dev->gap_start));

			/* Convert to ms and cap by LIRC_VALUE_MASK */
			do_div(dev->gap_duration, 1000);
			dev->gap_duration = min_t(u64, dev->gap_duration,
						  LIRC_VALUE_MASK);

			spin_lock_irqsave(&dev->lirc_fh_lock, flags);
			list_for_each_entry(fh, &dev->lirc_fh, list)
				kfifo_put(&fh->rawir,
					  LIRC_SPACE(dev->gap_duration));
			spin_unlock_irqrestore(&dev->lirc_fh_lock, flags);
			dev->gap = false;
		}

		sample = ev.pulse ? LIRC_PULSE(ev.duration / 1000) :
					LIRC_SPACE(ev.duration / 1000);
		dev_dbg(&dev->dev, "delivering %uus %s to lirc_dev\n",
			TO_US(ev.duration), TO_STR(ev.pulse));
	}

	/*
	 * bpf does not care about the gap generated above; that exists
	 * for backwards compatibility
	 */
	lirc_bpf_run(dev, sample);

	spin_lock_irqsave(&dev->lirc_fh_lock, flags);
	list_for_each_entry(fh, &dev->lirc_fh, list) {
		if (LIRC_IS_TIMEOUT(sample) && !fh->send_timeout_reports)
			continue;
		if (kfifo_put(&fh->rawir, sample))
			wake_up_poll(&fh->wait_poll, EPOLLIN | EPOLLRDNORM);
	}
	spin_unlock_irqrestore(&dev->lirc_fh_lock, flags);
}

/**
 * ir_lirc_scancode_event() - Send scancode data to lirc to be relayed to
 *		userspace. This can be called in atomic context.
 * @dev:	the struct rc_dev descriptor of the device
 * @lsc:	the struct lirc_scancode describing the decoded scancode
 */
void ir_lirc_scancode_event(struct rc_dev *dev, struct lirc_scancode *lsc)
{
	struct irctl *ir;
	unsigned int minor;
	int err;

	lsc->timestamp = ktime_get_ns();

	spin_lock_irqsave(&dev->lirc_fh_lock, flags);
	list_for_each_entry(fh, &dev->lirc_fh, list) {
		if (kfifo_put(&fh->scancodes, *lsc))
			wake_up_poll(&fh->wait_poll, EPOLLIN | EPOLLRDNORM);
	}

	if (!d->dev) {
		pr_err("dev pointer not filled in!\n");
		return -EINVAL;
	}

	if (!d->fops) {
		pr_err("fops pointer not filled in!\n");
		return -EINVAL;
	}

	if (d->code_length < 1 || d->code_length > (BUFLEN * 8)) {
		dev_err(d->dev, "code length must be less than %d bits\n",
								BUFLEN * 8);
		return -EBADRQC;
	}

	if (!d->rbuf && !(d->fops && d->fops->read &&
			  d->fops->poll && d->fops->unlocked_ioctl)) {
		dev_err(d->dev, "undefined read, poll, ioctl\n");
		return -EBADRQC;
	}

	mutex_lock(&lirc_dev_lock);

	/* find first free slot for driver */
	for (minor = 0; minor < MAX_IRCTL_DEVICES; minor++)
		if (!irctls[minor])
			break;

	if (minor == MAX_IRCTL_DEVICES) {
		dev_err(d->dev, "no free slots for drivers!\n");
		err = -ENOMEM;
		goto out_lock;
	}

	ir = kzalloc(sizeof(struct irctl), GFP_KERNEL);
	if (!ir) {
		err = -ENOMEM;
		goto out_lock;
	}

	mutex_init(&ir->irctl_lock);
	irctls[minor] = ir;
	d->irctl = ir;
	d->minor = minor;

	/* some safety check 8-) */
	d->name[sizeof(d->name)-1] = '\0';

	if (d->features == 0)
		d->features = LIRC_CAN_REC_LIRCCODE;

	ir->d = *d;

	if (LIRC_CAN_REC(d->features)) {
		err = lirc_allocate_buffer(irctls[minor]);
		if (err) {
			kfree(ir);
			goto out_lock;
		}
		d->rbuf = ir->buf;
	}

	device_initialize(&ir->dev);
	ir->dev.devt = MKDEV(MAJOR(lirc_base_dev), ir->d.minor);
	ir->dev.class = lirc_class;
	ir->dev.parent = d->dev;
	ir->dev.release = lirc_release;
	dev_set_name(&ir->dev, "lirc%d", ir->d.minor);

	cdev_init(&ir->cdev, d->fops);
	ir->cdev.owner = ir->d.owner;
	ir->attached = 1;

	err = cdev_device_add(&ir->cdev, &ir->dev);
	if (err)
		goto out_dev;

	mutex_unlock(&lirc_dev_lock);

	get_device(ir->dev.parent);

	dev_info(ir->d.dev, "lirc_dev: driver %s registered at minor = %d\n",
		 ir->d.name, ir->d.minor);

	return 0;

out_dev:
	put_device(&ir->dev);
out_lock:
	mutex_unlock(&lirc_dev_lock);

	return err;
}
EXPORT_SYMBOL_GPL(ir_lirc_scancode_event);

void lirc_unregister_driver(struct lirc_driver *d)
{
	struct rc_dev *dev = container_of(inode->i_cdev, struct rc_dev,
					  lirc_cdev);
	struct lirc_fh *fh = kzalloc(sizeof(*fh), GFP_KERNEL);
	unsigned long flags;
	int retval;

	if (!d || !d->irctl)
		return;

	ir = d->irctl;

	mutex_lock(&lirc_dev_lock);

	dev_dbg(ir->d.dev, "lirc_dev: driver %s unregistered from minor = %d\n",
		d->name, d->minor);

	ir->attached = 0;
	if (ir->open) {
		dev_dbg(ir->d.dev, LOGHEAD "releasing opened driver\n",
			d->name, d->minor);
		wake_up_interruptible(&ir->buf->wait_poll);
	}

	retval = rc_open(dev);
	if (retval)
		goto out_kfifo;

	cdev_device_del(&ir->cdev, &ir->dev);
	put_device(&ir->dev);
}
EXPORT_SYMBOL(lirc_unregister_driver);

int lirc_dev_fop_open(struct inode *inode, struct file *file)
{
	struct irctl *ir;
	int retval;

	if (iminor(inode) >= MAX_IRCTL_DEVICES) {
		pr_err("open result for %d is -ENODEV\n", iminor(inode));
		return -ENODEV;
	}

	if (mutex_lock_interruptible(&lirc_dev_lock))
		return -ERESTARTSYS;

	ir = irctls[iminor(inode)];
	mutex_unlock(&lirc_dev_lock);

	if (!ir) {
		retval = -ENODEV;
		goto error;
	}

	dev_dbg(ir->d.dev, LOGHEAD "open called\n", ir->d.name, ir->d.minor);

	if (ir->open) {
		retval = -EBUSY;
		goto error;
	}

	if (ir->d.rdev) {
		retval = rc_open(ir->d.rdev);
		if (retval)
			goto error;
	}

	if (ir->buf)
		lirc_buffer_clear(ir->buf);

	ir->open++;

	nonseekable_open(inode, file);

	return 0;

error:
	return retval;
}

static int ir_lirc_close(struct inode *inode, struct file *file)
{
	struct lirc_fh *fh = file->private_data;
	struct rc_dev *dev = fh->rc;
	unsigned long flags;

	spin_lock_irqsave(&dev->lirc_fh_lock, flags);
	list_del(&fh->list);
	spin_unlock_irqrestore(&dev->lirc_fh_lock, flags);

	if (dev->driver_type == RC_DRIVER_IR_RAW)
		kfifo_free(&fh->rawir);
	if (dev->driver_type != RC_DRIVER_IR_RAW_TX)
		kfifo_free(&fh->scancodes);
	kfree(fh);

	rc_close(dev);
	put_device(&dev->dev);

	return 0;
}

static ssize_t ir_lirc_transmit_ir(struct file *file, const char __user *buf,
				   size_t n, loff_t *ppos)
{
	struct lirc_fh *fh = file->private_data;
	struct rc_dev *dev = fh->rc;
	unsigned int *txbuf;
	struct ir_raw_event *raw = NULL;
	ssize_t ret;
	size_t count;
	ktime_t start;
	s64 towait;
	unsigned int duration = 0; /* signal duration in us */
	int i;

	ret = mutex_lock_interruptible(&dev->lock);
	if (ret)
		return ret;

	if (!dev->registered) {
		ret = -ENODEV;
		goto out_unlock;
	}

	if (!dev->tx_ir) {
		ret = -EINVAL;
		goto out_unlock;
	}

	if (fh->send_mode == LIRC_MODE_SCANCODE) {
		struct lirc_scancode scan;

		if (n != sizeof(scan)) {
			ret = -EINVAL;
			goto out_unlock;
		}

		if (copy_from_user(&scan, buf, sizeof(scan))) {
			ret = -EFAULT;
			goto out_unlock;
		}

		if (scan.flags || scan.keycode || scan.timestamp) {
			ret = -EINVAL;
			goto out_unlock;
		}

		/*
		 * The scancode field in lirc_scancode is 64-bit simply
		 * to future-proof it, since there are IR protocols encode
		 * use more than 32 bits. For now only 32-bit protocols
		 * are supported.
		 */
		if (scan.scancode > U32_MAX ||
		    !rc_validate_scancode(scan.rc_proto, scan.scancode)) {
			ret = -EINVAL;
			goto out_unlock;
		}

		raw = kmalloc_array(LIRCBUF_SIZE, sizeof(*raw), GFP_KERNEL);
		if (!raw) {
			ret = -ENOMEM;
			goto out_unlock;
		}

		ret = ir_raw_encode_scancode(scan.rc_proto, scan.scancode,
					     raw, LIRCBUF_SIZE);
		if (ret < 0)
			goto out_kfree_raw;

		/* drop trailing space */
		if (!(ret % 2))
			count = ret - 1;
		else
			count = ret;

		txbuf = kmalloc_array(count, sizeof(unsigned int), GFP_KERNEL);
		if (!txbuf) {
			ret = -ENOMEM;
			goto out_kfree_raw;
		}

		for (i = 0; i < count; i++)
			/* Convert from NS to US */
			txbuf[i] = DIV_ROUND_UP(raw[i].duration, 1000);

		if (dev->s_tx_carrier) {
			int carrier = ir_raw_encode_carrier(scan.rc_proto);

			if (carrier > 0)
				dev->s_tx_carrier(dev, carrier);
		}
	} else {
		if (n < sizeof(unsigned int) || n % sizeof(unsigned int)) {
			ret = -EINVAL;
			goto out_unlock;
		}

		count = n / sizeof(unsigned int);
		if (count > LIRCBUF_SIZE || count % 2 == 0) {
			ret = -EINVAL;
			goto out_unlock;
		}

		txbuf = memdup_user(buf, n);
		if (IS_ERR(txbuf)) {
			ret = PTR_ERR(txbuf);
			goto out_unlock;
		}
	}

	for (i = 0; i < count; i++) {
		if (txbuf[i] > IR_MAX_DURATION / 1000 - duration || !txbuf[i]) {
			ret = -EINVAL;
			goto out_kfree;
		}

		duration += txbuf[i];
	}

	start = ktime_get();

	ret = dev->tx_ir(dev, txbuf, count);
	if (ret < 0)
		goto out_kfree;

	kfree(txbuf);
	kfree(raw);
	mutex_unlock(&dev->lock);

	/*
	 * The lircd gap calculation expects the write function to
	 * wait for the actual IR signal to be transmitted before
	 * returning.
	 */
	towait = ktime_us_delta(ktime_add_us(start, duration),
				ktime_get());
	if (towait > 0) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(usecs_to_jiffies(towait));
	}

	return n;
out_kfree:
	kfree(txbuf);
out_kfree_raw:
	kfree(raw);
out_unlock:
	mutex_unlock(&dev->lock);
	return ret;
}

static long ir_lirc_ioctl(struct file *file, unsigned int cmd,
			  unsigned long arg)
{
	struct lirc_fh *fh = file->private_data;
	struct rc_dev *dev = fh->rc;
	u32 __user *argp = (u32 __user *)(arg);
	u32 val = 0;
	int ret;

	if (_IOC_DIR(cmd) & _IOC_WRITE) {
		ret = get_user(val, argp);
		if (ret)
			return ret;
	}

	ret = mutex_lock_interruptible(&dev->lock);
	if (ret)
		return ret;

	if (!ir->attached) {
		dev_err(ir->d.dev, LOGHEAD "ioctl result = -ENODEV\n",
			ir->d.name, ir->d.minor);
		return -ENODEV;
	}

	switch (cmd) {
	case LIRC_GET_FEATURES:
		if (dev->driver_type == RC_DRIVER_SCANCODE)
			val |= LIRC_CAN_REC_SCANCODE;

		if (dev->driver_type == RC_DRIVER_IR_RAW) {
			val |= LIRC_CAN_REC_MODE2;
			if (dev->rx_resolution)
				val |= LIRC_CAN_GET_REC_RESOLUTION;
		}

		if (dev->tx_ir) {
			val |= LIRC_CAN_SEND_PULSE;
			if (dev->s_tx_mask)
				val |= LIRC_CAN_SET_TRANSMITTER_MASK;
			if (dev->s_tx_carrier)
				val |= LIRC_CAN_SET_SEND_CARRIER;
			if (dev->s_tx_duty_cycle)
				val |= LIRC_CAN_SET_SEND_DUTY_CYCLE;
		}

		if (dev->s_rx_carrier_range)
			val |= LIRC_CAN_SET_REC_CARRIER |
				LIRC_CAN_SET_REC_CARRIER_RANGE;

		if (dev->s_learning_mode)
			val |= LIRC_CAN_USE_WIDEBAND_RECEIVER;

		if (dev->s_carrier_report)
			val |= LIRC_CAN_MEASURE_CARRIER;

		if (dev->max_timeout)
			val |= LIRC_CAN_SET_REC_TIMEOUT;

		break;

	/* mode support */
	case LIRC_GET_REC_MODE:
		if (dev->driver_type == RC_DRIVER_IR_RAW_TX)
			ret = -ENOTTY;
		else
			val = fh->rec_mode;
		break;

	case LIRC_SET_REC_MODE:
		switch (dev->driver_type) {
		case RC_DRIVER_IR_RAW_TX:
			ret = -ENOTTY;
			break;
		case RC_DRIVER_SCANCODE:
			if (val != LIRC_MODE_SCANCODE)
				ret = -EINVAL;
			break;
		case RC_DRIVER_IR_RAW:
			if (!(val == LIRC_MODE_MODE2 ||
			      val == LIRC_MODE_SCANCODE))
				ret = -EINVAL;
			break;
		}

		if (!ret)
			fh->rec_mode = val;
		break;

	case LIRC_GET_SEND_MODE:
		if (!dev->tx_ir)
			ret = -ENOTTY;
		else
			val = fh->send_mode;
		break;

	case LIRC_SET_SEND_MODE:
		if (!dev->tx_ir)
			ret = -ENOTTY;
		else if (!(val == LIRC_MODE_PULSE || val == LIRC_MODE_SCANCODE))
			ret = -EINVAL;
		else
			fh->send_mode = val;
		break;

	/* TX settings */
	case LIRC_SET_TRANSMITTER_MASK:
		if (!dev->s_tx_mask)
			ret = -ENOTTY;
		else
			ret = dev->s_tx_mask(dev, val);
		break;

	case LIRC_SET_SEND_CARRIER:
		if (!dev->s_tx_carrier)
			ret = -ENOTTY;
		else
			ret = dev->s_tx_carrier(dev, val);
		break;

	case LIRC_SET_SEND_DUTY_CYCLE:
		if (!dev->s_tx_duty_cycle)
			ret = -ENOTTY;
		else if (val <= 0 || val >= 100)
			ret = -EINVAL;
		else
			ret = dev->s_tx_duty_cycle(dev, val);
		break;

	/* RX settings */
	case LIRC_SET_REC_CARRIER:
		if (!dev->s_rx_carrier_range)
			ret = -ENOTTY;
		else if (val <= 0)
			ret = -EINVAL;
		else
			ret = dev->s_rx_carrier_range(dev, fh->carrier_low,
						      val);
		break;

	case LIRC_SET_REC_CARRIER_RANGE:
		if (!dev->s_rx_carrier_range)
			ret = -ENOTTY;
		else if (val <= 0)
			ret = -EINVAL;
		else
			fh->carrier_low = val;
		break;

	case LIRC_GET_REC_RESOLUTION:
		if (!dev->rx_resolution)
			ret = -ENOTTY;
		else
			val = dev->rx_resolution / 1000;
		break;

	case LIRC_SET_WIDEBAND_RECEIVER:
		if (!dev->s_learning_mode)
			ret = -ENOTTY;
		else
			ret = dev->s_learning_mode(dev, !!val);
		break;

	case LIRC_SET_MEASURE_CARRIER_MODE:
		if (!dev->s_carrier_report)
			ret = -ENOTTY;
		else
			ret = dev->s_carrier_report(dev, !!val);
		break;

	/* Generic timeout support */
	case LIRC_GET_MIN_TIMEOUT:
		if (!dev->max_timeout)
			ret = -ENOTTY;
		else
			val = DIV_ROUND_UP(dev->min_timeout, 1000);
		break;

	case LIRC_GET_MAX_TIMEOUT:
		if (!dev->max_timeout)
			ret = -ENOTTY;
		else
			val = dev->max_timeout / 1000;
		break;

	case LIRC_SET_REC_TIMEOUT:
		if (!dev->max_timeout) {
			ret = -ENOTTY;
		} else if (val > U32_MAX / 1000) {
			/* Check for multiply overflow */
			ret = -EINVAL;
		} else {
			u32 tmp = val * 1000;

			if (tmp < dev->min_timeout || tmp > dev->max_timeout)
				ret = -EINVAL;
			else if (dev->s_timeout)
				ret = dev->s_timeout(dev, tmp);
			else
				dev->timeout = tmp;
		}
		break;

	case LIRC_GET_REC_TIMEOUT:
		if (!dev->timeout)
			ret = -ENOTTY;
		else
			val = DIV_ROUND_UP(dev->timeout, 1000);
		break;

	case LIRC_SET_REC_TIMEOUT_REPORTS:
		if (dev->driver_type != RC_DRIVER_IR_RAW)
			ret = -ENOTTY;
		else
			fh->send_timeout_reports = !!val;
		break;

	default:
		ret = -ENOTTY;
	}

	if (!ret && _IOC_DIR(cmd) & _IOC_READ)
		ret = put_user(val, argp);

out:
	mutex_unlock(&dev->lock);
	return ret;
}

static unsigned int ir_lirc_poll(struct file *file,
				 struct poll_table_struct *wait)
{
	struct lirc_fh *fh = file->private_data;
	struct rc_dev *rcdev = fh->rc;
	unsigned int events = 0;

	poll_wait(file, &fh->wait_poll, wait);

	if (!rcdev->registered) {
		events = EPOLLHUP | EPOLLERR;
	} else if (rcdev->driver_type != RC_DRIVER_IR_RAW_TX) {
		if (fh->rec_mode == LIRC_MODE_SCANCODE &&
		    !kfifo_is_empty(&fh->scancodes))
			events = EPOLLIN | EPOLLRDNORM;

		if (fh->rec_mode == LIRC_MODE_MODE2 &&
		    !kfifo_is_empty(&fh->rawir))
			events = EPOLLIN | EPOLLRDNORM;
	}

	return events;
}

static ssize_t ir_lirc_read_mode2(struct file *file, char __user *buffer,
				  size_t length)
{
	struct lirc_fh *fh = file->private_data;
	struct rc_dev *rcdev = fh->rc;
	unsigned int copied;
	int ret;

	if (length < sizeof(unsigned int) || length % sizeof(unsigned int))
		return -EINVAL;

	do {
		if (kfifo_is_empty(&fh->rawir)) {
			if (file->f_flags & O_NONBLOCK)
				return -EAGAIN;

			ret = wait_event_interruptible(fh->wait_poll,
					!kfifo_is_empty(&fh->rawir) ||
					!rcdev->registered);
			if (ret)
				return ret;
		}

		if (!rcdev->registered)
			return -ENODEV;

		ret = mutex_lock_interruptible(&rcdev->lock);
		if (ret)
			return ret;
		ret = kfifo_to_user(&fh->rawir, buffer, length, &copied);
		mutex_unlock(&rcdev->lock);
		if (ret)
			return ret;
	} while (copied == 0);

	return copied;
}

static ssize_t ir_lirc_read_scancode(struct file *file, char __user *buffer,
				     size_t length)
{
	struct lirc_fh *fh = file->private_data;
	struct rc_dev *rcdev = fh->rc;
	unsigned int copied;
	int ret;

	if (length < sizeof(struct lirc_scancode) ||
	    length % sizeof(struct lirc_scancode))
		return -EINVAL;

	do {
		if (kfifo_is_empty(&fh->scancodes)) {
			if (file->f_flags & O_NONBLOCK)
				return -EAGAIN;

			ret = wait_event_interruptible(fh->wait_poll,
					!kfifo_is_empty(&fh->scancodes) ||
					!rcdev->registered);
			if (ret)
				return ret;
		}

		if (!rcdev->registered)
			return -ENODEV;

		ret = mutex_lock_interruptible(&rcdev->lock);
		if (ret)
			return ret;
		ret = kfifo_to_user(&fh->scancodes, buffer, length, &copied);
		mutex_unlock(&rcdev->lock);
		if (ret)
			return ret;
	} while (copied == 0);

	return copied;
}

static ssize_t ir_lirc_read(struct file *file, char __user *buffer,
			    size_t length, loff_t *ppos)
{
	struct lirc_fh *fh = file->private_data;
	struct rc_dev *rcdev = fh->rc;

	if (rcdev->driver_type == RC_DRIVER_IR_RAW_TX)
		return -EINVAL;

	if (!rcdev->registered)
		return -ENODEV;

	if (fh->rec_mode == LIRC_MODE_MODE2)
		return ir_lirc_read_mode2(file, buffer, length);
	else /* LIRC_MODE_SCANCODE */
		return ir_lirc_read_scancode(file, buffer, length);
}

static const struct file_operations lirc_fops = {
	.owner		= THIS_MODULE,
	.write		= ir_lirc_transmit_ir,
	.unlocked_ioctl	= ir_lirc_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ir_lirc_ioctl,
#endif
	.read		= ir_lirc_read,
	.poll		= ir_lirc_poll,
	.open		= ir_lirc_open,
	.release	= ir_lirc_close,
	.llseek		= no_llseek,
};

static void lirc_release_device(struct device *ld)
{
	struct rc_dev *rcdev = container_of(ld, struct rc_dev, lirc_dev);

	put_device(&rcdev->dev);
}

int ir_lirc_register(struct rc_dev *dev)
{
	const char *rx_type, *tx_type;
	int err, minor;

	minor = ida_simple_get(&lirc_ida, 0, RC_DEV_MAX, GFP_KERNEL);
	if (minor < 0)
		return minor;

	device_initialize(&dev->lirc_dev);
	dev->lirc_dev.class = lirc_class;
	dev->lirc_dev.parent = &dev->dev;
	dev->lirc_dev.release = lirc_release_device;
	dev->lirc_dev.devt = MKDEV(MAJOR(lirc_base_dev), minor);
	dev_set_name(&dev->lirc_dev, "lirc%d", minor);

	INIT_LIST_HEAD(&dev->lirc_fh);
	spin_lock_init(&dev->lirc_fh_lock);

	cdev_init(&dev->lirc_cdev, &lirc_fops);

	err = cdev_device_add(&dev->lirc_cdev, &dev->lirc_dev);
	if (err)
		goto out_ida;

	get_device(&dev->dev);

	switch (dev->driver_type) {
	case RC_DRIVER_SCANCODE:
		rx_type = "scancode";
		break;
	case RC_DRIVER_IR_RAW:
		rx_type = "raw IR";
		break;
	default:
		rx_type = "no";
		break;
	}

	if (dev->tx_ir)
		tx_type = "raw IR";
	else
		tx_type = "no";

	dev_info(&dev->dev, "lirc_dev: driver %s registered at minor = %d, %s receiver, %s transmitter",
		 dev->driver_name, minor, rx_type, tx_type);

	return 0;

out_ida:
	ida_simple_remove(&lirc_ida, minor);
	return err;
}

void ir_lirc_unregister(struct rc_dev *dev)
{
	unsigned long flags;
	struct lirc_fh *fh;

	dev_dbg(&dev->dev, "lirc_dev: driver %s unregistered from minor = %d\n",
		dev->driver_name, MINOR(dev->lirc_dev.devt));

	spin_lock_irqsave(&dev->lirc_fh_lock, flags);
	list_for_each_entry(fh, &dev->lirc_fh, list)
		wake_up_poll(&fh->wait_poll, EPOLLHUP | EPOLLERR);
	spin_unlock_irqrestore(&dev->lirc_fh_lock, flags);

	cdev_device_del(&dev->lirc_cdev, &dev->lirc_dev);
	ida_simple_remove(&lirc_ida, MINOR(dev->lirc_dev.devt));
}

int __init lirc_dev_init(void)
{
	int retval;

	lirc_class = class_create(THIS_MODULE, "lirc");
	if (IS_ERR(lirc_class)) {
		pr_err("class_create failed\n");
		return PTR_ERR(lirc_class);
	}

	retval = alloc_chrdev_region(&lirc_base_dev, 0, RC_DEV_MAX,
				     "BaseRemoteCtl");
	if (retval) {
		class_destroy(lirc_class);
		pr_err("alloc_chrdev_region failed\n");
		return retval;
	}

	pr_debug("IR Remote Control driver registered, major %d\n",
		 MAJOR(lirc_base_dev));

	return 0;
}

void __exit lirc_dev_exit(void)
{
	class_destroy(lirc_class);
	unregister_chrdev_region(lirc_base_dev, RC_DEV_MAX);
}

struct rc_dev *rc_dev_get_from_fd(int fd)
{
	struct fd f = fdget(fd);
	struct lirc_fh *fh;
	struct rc_dev *dev;

	if (!f.file)
		return ERR_PTR(-EBADF);

	if (f.file->f_op != &lirc_fops) {
		fdput(f);
		return ERR_PTR(-EINVAL);
	}

	fh = f.file->private_data;
	dev = fh->rc;

	get_device(&dev->dev);
	fdput(f);

	return dev;
}

MODULE_ALIAS("lirc_dev");
