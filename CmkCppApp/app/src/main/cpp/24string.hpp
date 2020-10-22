//-----------------------------------------------------------------------------
// Name:        24String.hpp
//
// Purpose:     This module is used to provide a string class. 
//              
// Author:      Yuancheng Liu
//
// Created:     2020/08/02
// Copyright:   < Sams Teach Your self C++ in 24 hours>
// License:     N.A
//-----------------------------------------------------------------------------
#include <iostream>
#include <string.h>

//-----------------------------------------------------------------------------
class String
{
public:
    String()
    {
        value = new char[1];
        value[0] = '\0';
        len = 0;
    };
    String(const char *const);
    String(const String &);
    ~String(){
        delete [] value; 
        len = 0;
    };

    // overload operators
    char &operator[](int offset);
    char operator[](int offset) const;
    String operator+(const String &);
    void operator+=(const String &);
    String &operator=(const String &);
    friend std::ostream& operator<<(std::ostream& stream, String& newString); 

    int getLen() const { return len; };
    const char *getString() const { return value; };

private:
    String(int);
    char *value;
    int len;
};

String::String(int newLen)
{
    len = newLen;
    value = new char[len + 1]; // Added the string end char '\0'
    for (int i = 0; i < len; i++)
        value[i] = '\0';
}

String::String(const char *const cString)
{
    len = strlen(cString);
    value = new char[len + 1];
    for (int i = 0; i < len; i++)
        value[i] = cString[i];
    value[len] = '\0';
}

String::String(const String &rhs)
{
    len = rhs.getLen();
    value = new char[len + 1];
    for (int i = 0; i < len; i++)
        value[i] = rhs[i];
    value[len] = '\0';
}

String &String::operator=(const String &rhs)
{
    if (this == &rhs)
        return *this;
    len = rhs.getLen();
    value = new char[len + 1];
    for (int i = 0; i < len; i++)
        value[i] = rhs[i];
    value[len] = '\0';
    return *this;
}

char &String::operator[](int offset)
{
    if (offset > len)
        return value[len - 1];
    else
        return value[offset];
}

char String::operator[](int offset) const
{
    if (offset > len)
        return value[len - 1];
    else
        return value[offset];
}

// Combine 2 String.
String String::operator+(const String &rhs)
{
    int totalLen = len + rhs.getLen();
    String temp(totalLen);
    int i;
    for (i = 0; i < len; i++)
        temp[i] = value[i];
    for (int j = 0; j < rhs.getLen(); i++, j++)
        temp[i] = rhs[j];
    temp[totalLen] = '\0';
    return temp;
}

// Append string 2 to string 1.
void String::operator+=(const String &rhs)
{
    int rhsLen = rhs.getLen();
    int totalLen = len + rhsLen;
    int i;
    String temp(totalLen);
    for (i = 0; i < len; i++)
        temp[i] = value[i];
    for (int j = 0; j < len; j++, i++)
        temp[i] = rhs[i - len];
    temp[totalLen] = '\0';
    *this = temp;
}

std::ostream& operator<<(std::ostream& stream, String& newString){
    stream << newString.getString();
    return stream;
}