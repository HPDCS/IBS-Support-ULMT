#ifndef IBS_API_H
#define IBS_API_H

/*
 * DOC: IBS ioctl commands
 *
 * ENABLE:        Activate IBS.
 *
 * DISABLE:       Deactivate IBS. You may still read buffered samples in the
 *                disabled state.
 *
 * IBS_REGISTER_THREAD:     Activate the control-flow-variation procedure for the
 *                          involved thread.
 *
 * IBS_UNREGISTER_THREAD:   Activate the control-flow-variation procedure for the
 *                          involved thread.
 *
 * SET_CUR_CNT:   Set the upper 23 bits of the 27-bit IBS op/cycle counter
 *                start value (the low 4 bits are randomized). Possible values
 *                satisfy 0 <= CUR_CNT < 2^23. (On IBS fetch devices, this
 *                command behaves like SET_CNT; see that ioctl for details.)
 *
 * SET_CNT:       Set the upper 16 bits of the 20-bit fetch counter (the low 4
 *                bits are randomized). Possible values satisfy 0<= CNT < 2^16
 *                *and* CNT <= MAX_CNT (see SET_MAX_CNT ioctl).  (On IBS op
 *                devices, this command behaves like SET_CUR_CNT; see that ioctl
 *                for details.)
 *
 *                This does nothing on Trinity (and earlier??) processors, on
 *                which the fetch counter always begins "at the maximum value"
 *                (see Erratum 719 in Revision Guide for AMD Family 15h Models
 *                10-1Fh Processors, Order #48931).
 *
 * GET_CUR_CNT:   Return the counter start value (*not* the current value).
 * GET_CNT:       Same as above.
 *
 * SET_MAX_CNT:   Valid inputs to this command are slightly different for fetch
 *                and op IBS flavors. When issued to an IBS *op* device, set the
 *                upper 23 bits of the 27-bit IBS op/cycle counter
 *                maximum value (the low 4 bits are always 0). Possible values
 *                satisfy 9 <= MAX_CNT < 2^23.
 *
 *                When issued to an IBS *fetch* device, set the upper 16 bits of
 *                the 20-bit fetch counter (the low 4 bits are always zero).
 *                Possible values satisfy 0<= MAX_CNT < 2^16 *and* CNT <= MAX_CNT
 *                (see SET_CNT ioctl).
 *
 * GET_MAX_CNT:   Return the counter maximum value.
 *
 * SET_CNT_CTL:   IBS op counter control - count ops or count cycles. Possible
 *                values are 0 to count cycles and 1 to count ops. Default 1.
 *                (Not meaningful for fetch devices.)
 *
 * GET_CNT_CTL:   Return the counter control value. (Not meaningful for fetch
 *                devices.)
 *
 * SET_RAND_EN:   IBS fetch randomization enable. Possible values are 0 to
 *                disable randomization (low 4 bits are set to 0h upon fetch
 *                enable), and 1 to enable. Default 1. (Not meaningful for op
 *                devices.)
 *
 * GET_RAND_EN:   Return the IBS fetch randomization enable value. (Not
 *                meaningful for op devices.)
 */

#define IBS_ENABLE                  (1U << 2)
#define IBS_DISABLE                 (1U << 3)
#define IBS_REGISTER_THREAD         (1U << 4)
#define IBS_UNREGISTER_THREAD       (1U << 5)
#define IBS_REGISTER_SAFE_MEM_ADDR  (1U << 6)
#define IBS_REGISTER_SAFE_MEM_SIZE  (1U << 7)
#define IBS_SET_TEXT_START          (1U << 8)
#define IBS_SET_TEXT_END            (1U << 9)

#endif        /* IBS_API_H */