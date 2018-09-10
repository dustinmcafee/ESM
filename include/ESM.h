#ifndef _ESM_H
#define _ESM_H
/*
 * Event Stream Model (ESM): Push model for input events.
 * Currently only works for certain mouse events.
 *
 * Dustin Colten McAfee <dmcafee2@my.utk.edu> <dustin.mcafee@my.maryvillecollege.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#include <linux/input.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/linkage.h>
#include <linux/kernel.h>
#include <linux/sched.h>

//#include <linux/syscalls.h>

//typedef void (*event_handler_t)(struct input_value*);
typedef void (*event_handler_t)(__u16, __u16, __s32);

typedef enum {MOUSE_RELATIVE_X,
		MOUSE_RELATIVE_Y,
		MOUSE_RELATIVE_WHEEL,
		MOUSE_RELATIVE_HWHEEL,
		MOUSE_BUTTON_LEFT,
		MOUSE_BUTTON_RIGHT,
		MOUSE_BUTTON_MIDDLE,
		EMU_MOUSE_BUTTON_LEFT,
		APPLICATION_LIST_SIZE} esm_event_t;

typedef struct {
	spinlock_t lock;
	struct list_head list;
	event_handler_t event_handler;
	struct task_struct* task;
	esm_event_t event_keycode;
}application_l;

typedef struct {
	application_l* mouse_rel_x_handlers;
	application_l* mouse_rel_y_handlers;
	application_l* mouse_rel_wheel_handlers;
	application_l* mouse_rel_hwheel_handlers;
	application_l* mouse_btn_left_handlers;
	application_l* mouse_btn_right_handlers;
	application_l* mouse_btn_middle_handlers;
	application_l* emu_mouse_btn_left_handlers;
	application_l* no_handlers;
}application_list_t;

typedef struct {
	__u16 type;
	__u16 code;
	__u32 value;
	struct task_struct* task;
}esm_tasklet_data;

application_l* handlers_for_event(esm_event_t keycode);

int esm_register(pid_t pid, __u16 type, __u16 code, event_handler_t event_handler);

int esm_register1(pid_t pid, __u16 type, __u16 code, event_handler_t event_handler);

int esm_dispatch(struct input_value* event, struct task_struct* task);

int esm_wait(pid_t pid);

int esm_wait1(pid_t pid);

int esm_interpret(struct input_value* event);

#endif	//_ESM_H
