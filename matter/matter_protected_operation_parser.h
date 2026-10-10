/* Exact Matter IM control-plane reject-list parser.
 *
 * Include from aflnet.c after matter_status_parser.h. The surrounding
 * translation unit supplies matter_msg_header_len(),
 * matter_payload_header_len(), matter_tlv_skip(), matter_element_header(),
 * and matter_child(). Malformed bytes are never matched by numeric pattern;
 * every rejected operation must be recovered from its schema-defined path.
 */
#ifndef MATTER_PROTECTED_OPERATION_PARSER_H
#define MATTER_PROTECTED_OPERATION_PARSER_H

#ifndef MATTER_PROTECTED_ACCESS_CONTROL
#define MATTER_PROTECTED_ACCESS_CONTROL  (1u << 0)
#define MATTER_PROTECTED_GROUP_KEY       (1u << 1)
#define MATTER_PROTECTED_FABRIC          (1u << 2)
#define MATTER_PROTECTED_ADMIN           (1u << 3)
#endif

#define MATTER_IM_WRITE_REQUEST          0x06
#define MATTER_IM_INVOKE_REQUEST         0x08
#define MATTER_PROTOCOL_ID_IM            0x0001

static int matter_policy_uint32(const unsigned char *b, unsigned int p,
                                unsigned int end, unsigned int *value) {
  unsigned char type;
  unsigned int width, header, i;
  unsigned long long decoded = 0;
  if (p >= end) return 0;
  type = b[p] & 31;
  if (type < 4 || type > 7) return 0;
  width = 1u << (type & 3);
  header = matter_element_header(b[p]);
  if (end - p < header + width) return 0;
  for (i = 0; i < width; ++i)
    decoded |= (unsigned long long)b[p + header + i] << (8 * i);
  if (decoded > 0xffffffffULL) return 0;
  *value = (unsigned int)decoded;
  return 1;
}

static unsigned int matter_policy_command(unsigned int cluster,
                                          unsigned int command) {
  if (cluster == 0x003f && command == 0x00)
    return MATTER_PROTECTED_GROUP_KEY;
  if (cluster == 0x003e &&
      (command == 0x04 || command == 0x06 || command == 0x07 ||
       command == 0x0a || command == 0x0b))
    return MATTER_PROTECTED_FABRIC;
  if (cluster == 0x003c && command == 0x02)
    return MATTER_PROTECTED_ADMIN;
  return 0;
}

static unsigned int matter_policy_invoke(const unsigned char *b,
                                         unsigned int root,
                                         unsigned int end) {
  unsigned int array = matter_child(b, root, end, 2);
  unsigned int mask = 0, p, limit;
  long span;
  if (array >= end || (b[array] & 31) != 0x16) return 0;
  span = matter_tlv_skip(b, array, end);
  if (span <= 0) return 0;
  limit = array + (unsigned int)span - 1;
  p = array + matter_element_header(b[array]);
  while (p < limit) {
    unsigned int item_end, path, cluster, command;
    long item_span = matter_tlv_skip(b, p, limit);
    if (item_span <= 0) break;
    item_end = p + (unsigned int)item_span;
    path = matter_child(b, p, item_end, 0);
    if (path < item_end &&
        matter_policy_uint32(b, matter_child(b, path, item_end, 1),
                             item_end, &cluster) &&
        matter_policy_uint32(b, matter_child(b, path, item_end, 2),
                             item_end, &command))
      mask |= matter_policy_command(cluster, command);
    p = item_end;
  }
  return mask;
}

static unsigned int matter_policy_write(const unsigned char *b,
                                        unsigned int root,
                                        unsigned int end) {
  unsigned int array = matter_child(b, root, end, 2);
  unsigned int mask = 0, p, limit;
  long span;
  if (array >= end || (b[array] & 31) != 0x16) return 0;
  span = matter_tlv_skip(b, array, end);
  if (span <= 0) return 0;
  limit = array + (unsigned int)span - 1;
  p = array + matter_element_header(b[array]);
  while (p < limit) {
    unsigned int item_end, path, cluster, attribute;
    long item_span = matter_tlv_skip(b, p, limit);
    if (item_span <= 0) break;
    item_end = p + (unsigned int)item_span;
    path = matter_child(b, p, item_end, 1);
    if (path < item_end &&
        matter_policy_uint32(b, matter_child(b, path, item_end, 3),
                             item_end, &cluster) &&
        matter_policy_uint32(b, matter_child(b, path, item_end, 4),
                             item_end, &attribute) &&
        cluster == 0x001f && attribute == 0x0000)
      mask |= MATTER_PROTECTED_ACCESS_CONTROL;
    p = item_end;
  }
  return mask;
}

unsigned int matter_protected_operations(unsigned char *buf,
                                         unsigned int size) {
  unsigned int payload_header, protocol_offset, root, end;
  unsigned int protocol;
  unsigned char flags, opcode;
  int message_header, payload_header_len;
  long root_span;
  if (buf == NULL) return 0;
  message_header = matter_msg_header_len(buf, 0, size);
  if (message_header < 0) return 0;
  payload_header = (unsigned int)message_header;
  payload_header_len = matter_payload_header_len(buf, payload_header, size);
  if (payload_header_len < 0) return 0;
  flags = buf[payload_header];
  opcode = buf[payload_header + 1];
  protocol_offset = payload_header + 4 + ((flags & 0x10) ? 2 : 0);
  if (protocol_offset + 2 > size) return 0;
  protocol = (unsigned int)buf[protocol_offset] |
             ((unsigned int)buf[protocol_offset + 1] << 8);
  if (protocol != MATTER_PROTOCOL_ID_IM ||
      (opcode != MATTER_IM_WRITE_REQUEST &&
       opcode != MATTER_IM_INVOKE_REQUEST))
    return 0;
  root = payload_header + (unsigned int)payload_header_len;
  if (root >= size || buf[root] != 0x15) return 0;
  root_span = matter_tlv_skip(buf, root, size);
  if (root_span <= 0 || (unsigned long)root_span > size - root) return 0;
  end = root + (unsigned int)root_span;
  return opcode == MATTER_IM_INVOKE_REQUEST ?
      matter_policy_invoke(buf, root, end) :
      matter_policy_write(buf, root, end);
}

unsigned int matter_tcp_protected_operations(unsigned char *buf,
                                             unsigned int size) {
  unsigned int declared;
  if (buf == NULL || size < 4) return 0;
  declared = (unsigned int)buf[0] |
             ((unsigned int)buf[1] << 8) |
             ((unsigned int)buf[2] << 16) |
             ((unsigned int)buf[3] << 24);
  if (declared == 0 || declared > size - 4) return 0;
  return matter_protected_operations(buf + 4, declared);
}

#undef MATTER_PROTOCOL_ID_IM
#undef MATTER_IM_INVOKE_REQUEST
#undef MATTER_IM_WRITE_REQUEST

#endif
