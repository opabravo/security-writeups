
# What is an IDOR?

IDOR stands for Insecure Direct Object Reference and is a type of access control vulnerability.  

This type of vulnerability can occur when a web server receives user-supplied input to retrieve objects (files, data, documents), too much trust has been placed on the input data, and it is not validated on the server-side to confirm the requested object belongs to the user requesting it.

## Summary

- It's a type of broken access control 
- It give to much trust to user input via direct object reference

IDOR Example:
`userinfo?id=(a or any)`

Broken Access Control Example:
cookie、JWT token、sessionid

# An IDOR Example

# Finding IDORs in Encoded IDs

# Finding IDORs in Hashed IDs

# Finding IDORs in Unpredictable IDs

# Where are IDORs located

