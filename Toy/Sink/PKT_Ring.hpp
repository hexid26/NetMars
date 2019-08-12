#include <string.h>
#include <string>

class PKT_Ring {
private:
  /* data */
public:
  std::string name;
  size_t capacity; // 可以容纳的数据包的数量，每个包的预留大小为1514(1500+14)
  constexpr uint16_t max_pkt_length = 1514;
  char *pkt_raw_data = NULL;
  long long head = 1;
  long long tail = 0;
  bool is_full = false;
  PKT_Ring(std::string name_in, size_t capacity_in);
  ~PKT_Ring();
  long long pop(char *&dst);
  long long push(char *buffer);
};

PKT_Ring::PKT_Ring(std::string name_in, size_t capacity_in) {
  name = name_in;
  capacity = capacity_in;
  pkt_raw_data = (char *)malloc(capacity * max_pkt_length);
  if (pkt_raw_data == NULL) {
    printf("ERROR::malloc for ring \'%s\' failed.\n", name.c_str());
  }
  printf("DEBUG::ring \'%s\' init done, capacity = %lu MB\n", name.c_str(), capacity * max_pkt_length / 1024 / 1024);
}

PKT_Ring::~PKT_Ring() { free(pkt_raw_data); }

long long PKT_Ring::pop(char *&dst) {
  if ((tail + 1) % capacity != head) {
    memcpy(dst, pkt_raw_data + head * max_pkt_length, max_pkt_length);
    return (++tail) % capacity;
  } else {
    return -1;
  }
}

long long PKT_Ring::push(char *buffer) {
  if (head != tail) {
    memcpy(pkt_raw_data + head * max_pkt_length, buffer, max_pkt_length);
    head = (1 + head) % capacity;
    return head;
  } else {
    return -1;
  }
}
