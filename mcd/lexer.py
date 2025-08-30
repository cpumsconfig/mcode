# -*- coding: utf-8 -*-
def tokenize(src: str):
    # 支持行末 \ 续行
    src = src.replace("\\\n", " ")
    # 先处理注释：移除#号到行尾的内容
    lines = src.split('\n')
    processed_lines = []
    for line in lines:
        if '#' in line:
            line = line[:line.index('#')]
        processed_lines.append(line)
    src = '\n'.join(processed_lines)
    
    tokens, cur, s = [], "", False
    line_num = 1
    for c in src:
        if c == '\n':
            line_num += 1
        if c == '"':
            s = not s
            cur += c
            if not s:
                tokens.append((cur, line_num))
                cur = ""
        elif c.isspace() and not s:
            if cur: 
                tokens.append((cur, line_num))
                cur = ""
        else:
            # 特殊处理冒号和标签
            if c == ':' and not s:
                if cur:
                    tokens.append((cur, line_num))
                    cur = ""
                tokens.append((c, line_num))
            else:
                cur += c
    if cur: 
        tokens.append((cur, line_num))
    return tokens

