CXX=gcc
EXTRA_LIB_DIR=-L ../src/OBS_API/lib -L ../self_dev/huaweisecurec/lib
EXTRA_INCLUDE_DIR=-I ../src/OBS_API/include -I ../self_dev/huaweisecurec/include

LIB=-leSDKOBSS3 -lsecurec
LINKOPT=$(EXTRA_LIB_DIR) $(LIB) 

TARGET=s3

SRC=$(wildcard *.c)
export LD_LIBRARY_PATH=../lib
all:$(TARGET)
$(TARGET):$(OBJ)
	$(CXX) $(SRC) $(EXTRA_INCLUDE_DIR) $(LINKOPT) -fstack-protector --param ssp-buffer-size=4 -Wstack-protector -Wl,--disable-new-dtags,--rpath ../src/OBS_API/lib -Wl,-z,relro,-z,now -Wl,-z,noexecstack -fPIC -o $(TARGET)
clean:
	rm -f s3;rm -f *.o
