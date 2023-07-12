[[4. Game Zone#MySQL Injection Manually (Union)]]

## Cheat Sheet

All in one depth - https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet

## Commands 

- `UNION ALL` - 聯集
- `UNION` - 交集
- - Limit
    - `LIMIT 0,1` , `LIMIT 1,1` , `LIMIT 2,1` ...
        - Select only 1 data
    - `LIMIT 1 OFFSET 0`, `LIMIT 1 OFFSET 1`
- Substring
    - `SUBSTRING("ABC",1,1)`
        - Will return `A`
    - `SUBSTRING("ABC",2,1)`
        - Will return `B`
- ASCII
    - `ASCII("A")`
        - Will Return `65`
- Concat
    - `concat(1,':',2)`
        - Will return `1:2`
- Group concat
    - `group_concat()`
    - Concatenate multiple data to one line string
- String Length
    - `length()`
- Row counts
    - `count()`
- Current db
    - `database()`
- Distinct item
    - `distinct()`

