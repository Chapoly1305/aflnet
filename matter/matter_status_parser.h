/* Matter IM status extraction. Include after matter_tlv_skip().
 * Only direct children at schema-defined paths count as StatusIB fields.
 * Attribute data, command data, and byte strings are never searched for tags.
 */
#ifndef MATTER_STATUS_PARSER_H
#define MATTER_STATUS_PARSER_H

static unsigned int matter_element_header(unsigned char ctrl) {
  static const unsigned int tags[] = {0, 1, 2, 4, 2, 4, 6, 8};
  return 1 + tags[ctrl >> 5];
}

/* Return the offset of a direct context child, or end if absent/malformed. */
static unsigned int matter_child(const unsigned char *b, unsigned int parent,
                                 unsigned int end, unsigned char tag) {
  if (parent >= end || (b[parent] & 31) < 0x15 || (b[parent] & 31) > 0x17)
    return end;
  long span = matter_tlv_skip(b, parent, end);
  if (span < 0) return end;
  unsigned int limit = parent + (unsigned int)span - 1;
  unsigned int p = parent + matter_element_header(b[parent]);
  while (p < limit) {
    long n = matter_tlv_skip(b, p, limit);
    if (n <= 0) return end;
    if ((b[p] & 0xe0) == 0x20 && p + 1 < limit && b[p + 1] == tag)
      return p;
    p += (unsigned int)n;
  }
  return end;
}

static int matter_status_uint(const unsigned char *b, unsigned int p,
                              unsigned int end, unsigned int *status) {
  if (p >= end) return 0;
  unsigned char type = b[p] & 31;
  if (type < 4 || type > 7) return 0;
  unsigned int width = 1u << (type & 3);
  unsigned int h = matter_element_header(b[p]);
  if (end - p < h + width) return 0;
  unsigned long long v = 0;
  unsigned int i;
  for (i = 0; i < width; ++i) v |= (unsigned long long)b[p + h + i] << (8 * i);
  if (v > 255) return 0;
  *status = (unsigned int)v;
  return 1;
}

static int matter_status_ib(const unsigned char *b, unsigned int p,
                            unsigned int end, unsigned int *status) {
  if (p >= end || (b[p] & 31) != 0x15) return 0;
  return matter_status_uint(b, matter_child(b, p, end, 0), end, status);
}

static int matter_status_array(const unsigned char *b, unsigned int array,
                               unsigned int end, unsigned char opcode,
                               unsigned int *status) {
  if (array >= end || (b[array] & 31) != 0x16) return 0;
  long span = matter_tlv_skip(b, array, end);
  if (span < 0) return 0;
  unsigned int limit = array + (unsigned int)span - 1;
  unsigned int p = array + matter_element_header(b[array]);
  while (p < limit) {
    long n = matter_tlv_skip(b, p, limit);
    if (n <= 0) return 0;
    unsigned int item_end = p + (unsigned int)n;
    if (b[p] == 0x15) {
      unsigned int carrier = p;
      if (opcode == 0x09) carrier = matter_child(b, p, item_end, 1);
      if (opcode == 0x05) carrier = matter_child(b, p, item_end, 0);
      if (carrier < item_end && (b[carrier] & 31) == 0x15 &&
          matter_status_ib(b, matter_child(b, carrier, item_end, 1), item_end, status))
        return 1;
    }
    p = item_end;
  }
  return 0;
}

static int matter_im_status(const unsigned char *b, unsigned int root,
                            unsigned int end, unsigned char opcode,
                            unsigned int *status) {
  if (root >= end || b[root] != 0x15) return 0;
  if (opcode == 0x01)
    return matter_status_uint(b, matter_child(b, root, end, 0), end, status);
  if (opcode == 0x07)
    return matter_status_array(b, matter_child(b, root, end, 0), end, opcode, status);
  if (opcode == 0x09)
    return matter_status_array(b, matter_child(b, root, end, 1), end, opcode, status);
  if (opcode == 0x05) {
    if (matter_status_array(b, matter_child(b, root, end, 1), end, opcode, status)) return 1;
    return matter_status_array(b, matter_child(b, root, end, 2), end, opcode, status);
  }
  return 0;
}
#endif
