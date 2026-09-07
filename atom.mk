
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libtransport-tls
LOCAL_CATEGORY_PATH := libs
LOCAL_DESCRIPTION := TLS Transport library
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_CFLAGS := -DTTLS_API_EXPORTS -fvisibility=hidden -std=gnu99
LOCAL_SRC_FILES := \
	src/ttls.c \
	src/ttls_async.c \
	src/ttls_bio.c \
	src/ttls_socket.c \
	src/ttls_utils.c
LOCAL_LIBRARIES := \
	libcrypto \
	libfutils \
	libpomp \
	libtransport-packet \
	libtransport-socket \
	libulog

include $(BUILD_LIBRARY)


ifdef TARGET_TEST

include $(CLEAR_VARS)

LOCAL_MODULE := tst-libtransport-tls
LOCAL_CFLAGS := -DTARGET_TEST -D_GNU_SOURCE -std=gnu99
LOCAL_C_INCLUDES := $(LOCAL_PATH)/src
LOCAL_SRC_FILES := \
	tests/ttls_test.c \
	tests/ttls_test_fakes.c \
	tests/ttls_test_socket.c \
	tests/ttls_test_bio.c \
	tests/ttls_test_async.c \
	tests/ttls_test_utils.c \
	tests/ttls_test_async_engine.c \
	src/ttls_bio.c \
	src/ttls_async.c
# ttls_bio.c/ttls_async.c are recompiled here (rather than only linked via
# libtransport-tls below) because their entry points aren't TTLS_API and the
# library is built with -fvisibility=hidden, so ttls_test_bio.c/
# ttls_test_async.c calling them directly need their own copy in this binary.
LOCAL_LIBRARIES := \
	libcrypto \
	libcunit \
	libfutils \
	libpomp \
	libtransport-packet \
	libtransport-socket \
	libtransport-tls \
	libulog

include $(BUILD_EXECUTABLE)

endif


include $(CLEAR_VARS)

LOCAL_MODULE := ttls-server
LOCAL_CATEGORY_PATH := multimedia
LOCAL_DESCRIPTION := TLS Transport library server test program
LOCAL_CFLAGS := -std=gnu99
LOCAL_SRC_FILES := \
	tools/ttls_server.c
LOCAL_LIBRARIES := \
	libcrypto \
	libfutils \
	libpomp \
	libtransport-packet \
	libtransport-socket \
	libtransport-tls \
	libulog

include $(BUILD_EXECUTABLE)


include $(CLEAR_VARS)

LOCAL_MODULE := ttls-client
LOCAL_CATEGORY_PATH := multimedia
LOCAL_DESCRIPTION := TLS Transport library client test program
LOCAL_CFLAGS := -std=gnu99
LOCAL_SRC_FILES := \
	tools/ttls_client.c
LOCAL_LIBRARIES := \
	libcrypto \
	libfutils \
	libpomp \
	libtransport-packet \
	libtransport-socket \
	libtransport-tls \
	libulog

include $(BUILD_EXECUTABLE)
