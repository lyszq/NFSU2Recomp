#ifndef NFSU2_WIN32_FULL_PATH_H
#define NFSU2_WIN32_FULL_PATH_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* GetFullPathNameA uses a guest Windows path namespace. Keep it independent
 * from the host filesystem and from the iOS container's real path. */
#define WIN32_FULL_PATH_MAX_CHARS 32767u
#define WIN32_FULL_PATH_STORAGE (WIN32_FULL_PATH_MAX_CHARS + 1u)
#define WIN32_FULL_PATH_CWD "C:\\NFSU2"

enum Win32FullPathError {
    WIN32_FULL_PATH_ERROR_INVALID_DRIVE = 15u,
    WIN32_FULL_PATH_ERROR_NOT_ENOUGH_MEMORY = 8u,
    WIN32_FULL_PATH_ERROR_INVALID_PARAMETER = 87u,
    WIN32_FULL_PATH_ERROR_INVALID_NAME = 123u,
    WIN32_FULL_PATH_ERROR_FILENAME_EXCED_RANGE = 206u,
    WIN32_FULL_PATH_ERROR_NOACCESS = 998u
};

typedef struct Win32FullPathInfo {
    size_t length;             /* path bytes, excluding the terminating NUL */
    size_t file_part_offset;   /* ANSI byte offset from the start of the path */
    int has_file_part;
} Win32FullPathInfo;

static inline int win32_full_path_is_separator(char ch)
{
    return ch == '\\' || ch == '/';
}

static inline int win32_full_path_is_alpha(char ch)
{
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
}

static inline int win32_full_path_append(char *out, size_t *length,
                                         const char *bytes, size_t count)
{
    if (count > WIN32_FULL_PATH_MAX_CHARS - *length) return 0;
    memcpy(out + *length, bytes, count);
    *length += count;
    return 1;
}

static inline int win32_full_path_append_segment(char *out, size_t *length,
                                                 const char *segment,
                                                 size_t count)
{
    if (*length > 3u && out[*length - 1u] != '\\') {
        if (*length >= WIN32_FULL_PATH_MAX_CHARS) return 0;
        out[(*length)++] = '\\';
    }
    return win32_full_path_append(out, length, segment, count);
}

static inline void win32_full_path_pop_segment(char *out, size_t *length)
{
    size_t cursor = *length;
    while (cursor > 3u && out[cursor - 1u] != '\\') cursor--;
    if (cursor > 3u) *length = cursor - 1u;
    else *length = 3u;
}

/* Normalize lexically in the guest's C: namespace. Relative and C:-relative
 * names use the fixed process current directory C:\\NFSU2. A single leading
 * separator is rooted at C:\\; UNC/device namespaces and other drives are
 * rejected because this runtime has no such guest namespace. */
static inline int win32_full_path_normalize(const char *input,
                                            char output[WIN32_FULL_PATH_STORAGE],
                                            Win32FullPathInfo *info,
                                            uint32_t *error)
{
    char normalized[WIN32_FULL_PATH_STORAGE];
    size_t input_length = 0;
    size_t cursor = 0;
    size_t length = 3u;
    int relative = 0;
    int trailing = 0;

    if (error) *error = WIN32_FULL_PATH_ERROR_INVALID_PARAMETER;
    if (!input || !output || !info) return 0;

    while (input_length <= WIN32_FULL_PATH_MAX_CHARS && input[input_length])
        input_length++;
    if (input_length > WIN32_FULL_PATH_MAX_CHARS) {
        if (error) *error = WIN32_FULL_PATH_ERROR_FILENAME_EXCED_RANGE;
        return 0;
    }
    if (input_length == 0u) {
        if (error) *error = WIN32_FULL_PATH_ERROR_INVALID_NAME;
        return 0;
    }

    /* A double leading slash denotes a network/device path, which is outside
     * this runtime's fixed single-drive guest namespace. */
    if (input_length >= 2u && win32_full_path_is_separator(input[0]) &&
        win32_full_path_is_separator(input[1])) {
        if (error) *error = WIN32_FULL_PATH_ERROR_INVALID_NAME;
        return 0;
    }

    normalized[0] = 'C';
    normalized[1] = ':';
    normalized[2] = '\\';

    if (input_length >= 2u && input[1] == ':') {
        if (!win32_full_path_is_alpha(input[0])) {
            if (error) *error = WIN32_FULL_PATH_ERROR_INVALID_NAME;
            return 0;
        }
        if (input[0] != 'C' && input[0] != 'c') {
            if (error) *error = WIN32_FULL_PATH_ERROR_INVALID_DRIVE;
            return 0;
        }
        cursor = 2u;
        if (cursor < input_length && win32_full_path_is_separator(input[cursor])) {
            while (cursor < input_length && win32_full_path_is_separator(input[cursor]))
                cursor++;
        } else {
            relative = 1;
        }
    } else if (win32_full_path_is_separator(input[0])) {
        cursor = 1u;
        while (cursor < input_length && win32_full_path_is_separator(input[cursor]))
            cursor++;
    } else {
        relative = 1;
    }

    if (relative && !win32_full_path_append_segment(
            normalized, &length, WIN32_FULL_PATH_CWD + 3u,
            sizeof(WIN32_FULL_PATH_CWD) - 4u)) {
        if (error) *error = WIN32_FULL_PATH_ERROR_FILENAME_EXCED_RANGE;
        return 0;
    }

    trailing = win32_full_path_is_separator(input[input_length - 1u]);
    while (cursor < input_length) {
        size_t start;
        size_t count;

        while (cursor < input_length && win32_full_path_is_separator(input[cursor]))
            cursor++;
        if (cursor == input_length) break;

        start = cursor;
        while (cursor < input_length && !win32_full_path_is_separator(input[cursor]))
            cursor++;
        count = cursor - start;

        if (count == 1u && input[start] == '.') {
            continue;
        }
        if (count == 2u && input[start] == '.' && input[start + 1u] == '.') {
            win32_full_path_pop_segment(normalized, &length);
            continue;
        }
        if (!win32_full_path_append_segment(normalized, &length,
                                            input + start, count)) {
            if (error) *error = WIN32_FULL_PATH_ERROR_FILENAME_EXCED_RANGE;
            return 0;
        }
    }

    if (trailing && normalized[length - 1u] != '\\') {
        if (length >= WIN32_FULL_PATH_MAX_CHARS) {
            if (error) *error = WIN32_FULL_PATH_ERROR_FILENAME_EXCED_RANGE;
            return 0;
        }
        normalized[length++] = '\\';
    }
    normalized[length] = '\0';

    info->length = length;
    info->file_part_offset = 0u;
    info->has_file_part = 0;
    if (length > 3u && !trailing) {
        size_t part = length;
        while (part > 3u && normalized[part - 1u] != '\\') part--;
        info->file_part_offset = part;
        info->has_file_part = 1;
    }

    memcpy(output, normalized, length + 1u);
    if (error) *error = 0u;
    return 1;
}

#endif
