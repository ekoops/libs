#include "../../event_class/event_class.h"

#ifdef __NR_flock
TEST(SyscallExit, flockX) {
	auto evt_test = get_syscall_event_test(__NR_flock, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	int32_t mock_fd = -1;
	int32_t operation = LOCK_EX;
	assert_syscall_state(SYSCALL_FAILURE, "flock", syscall(__NR_flock, mock_fd, operation));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure()) {
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: fd (type: PT_FD) */
	evt_test->assert_numeric_param(2, (int64_t)mock_fd);

	/* Parameter 3: operation (type: PT_FLAGS32) */
	evt_test->assert_numeric_param(3, (uint32_t)PPM_LOCK_EX);

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(3);
}
#endif
