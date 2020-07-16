TARGET := securesocks5

CC := g++ -DDEBUG -DUSE_STANDALONE_ASIO -DTEST -std=c++17  

#注意每行后面不要有空格，否则会算到目录名里面，导致问题
SRC_DIR := ./src 
BUILD_DIR = tmp
OBJ_DIR = $(BUILD_DIR)/obj
DEPS_DIR  = $(BUILD_DIR)/deps

#这里添加其他头文件路径
INC_DIR = \
	-I./src \
	-I./asio-1.16.1/include 

#这里添加编译参数 -DNDEBUG(release加这个, 并去掉-ggdb3)
CC_FLAGS := $(INC_DIR) -ggdb3  -Wextra -Wall -march=x86-64 #-ldl -std=gnu++17 #debug
#CC_FLAGS := $(INC_DIR) -O3 -DNDEBUG -Wextra -Wall -march=x86-64 -std=gnu++17 # release

LNK_LIBS += `pkg-config --static --libs grpc++ protobuf-lite openssl glog` 

#这里递归遍历3级子目录
DIRS := $(shell find $(SRC_DIR) -maxdepth 3 -type d)

#将每个子目录添加到搜索路径
VPATH = $(DIRS)

#查找src_dir下面包含子目录的所有cc文件
SOURCES   = $(foreach dir, $(DIRS), $(wildcard $(dir)/*.cc))  
SOURCES := $(sort $(SOURCES))
OBJS   = $(addprefix $(OBJ_DIR)/,$(patsubst %.cc,%.o,$(notdir $(SOURCES))))  
DEPS  = $(addprefix $(DEPS_DIR)/, $(patsubst %.cc,%.d,$(notdir $(SOURCES))))  
$(TARGET):$(OBJS)
	@echo "Link...";
	$(CC) $^ $(LNK_FLAGS) $(LNK_LIBS) $(CC_FLAGS) -o bin/$@
	@echo "DONE!"

#编译之前要创建OBJ目录，确保目录存在
$(OBJ_DIR)/%.o:%.cc
	@if [ ! -d $(OBJ_DIR) ]; then mkdir -p $(OBJ_DIR); fi;\
	$(CC) -c $(INC_DIR) $(LNK_FLAGS) $(CC_FLAGS) -o $@ $<
	@echo $@

#编译之前要创建DEPS目录，确保目录存在 #前面加@表示隐藏命令的执行打印
$(DEPS_DIR)/%.d:%.cc
	@if [ ! -d $(DEPS_DIR) ]; then mkdir -p $(DEPS_DIR); fi;
	@set -e; rm -f $@;\
	$(CC) -MM $< $(INC_DIR) > $@.$$$$;\
	sed 's,\($*\)\.o[ :]*, $(OBJ_DIR)/\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$; \
	echo Build: $@;
#前面加-表示忽略错误
-include $(DEPS)
.PHONY : clean
clean:
	@rm -rf $(BUILD_DIR) bin/$(TARGET);
	@echo "area clear!"

