//-----------------------------------------------------------------------------
// Name:        24linkList.hpp
//
// Purpose:     This module is used to provide a one way linked list to save and 
//              sort the insert data.
// Author:      Yuancheng Liu
//
// Created:     2020/08/02
// Copyright:   < Sams Teach Your self C++ in 24 hours>
// License:     N.A
//-----------------------------------------------------------------------------
#include <iostream>

//-----------------------------------------------------------------------------
enum
{
    kIsSmaller,
    kIsLarger,
    kIsSame
};

// Date class used for testing. Usage: LinkedList<Data> ll;
class Data
{
public:
    Data(int newVal) : value(newVal){};
    ~Data()
    {
        std::cout << "Deleting Data object with value: " << value << "\n";
    };
    int compare(const Data &);
    void show() { std::cout << value << "\n"; };

private:
    int value;
};

int Data::compare(const Data &otherData)
{
    if (value < otherData.value)
    {
        return kIsSmaller;
    }
    else if (value > otherData.value)
    {
        return kIsSmaller;
    }
    else
    {
        return kIsSame;
    }
}

//-----------------------------------------------------------------------------
// Node: 
template <class T> 
class Node
{
public:
    Node(){};
    virtual ~Node(){};
    virtual Node *insert(T *object) = 0;
    virtual void show() = 0;

private:
};

// Internal Node:
template <class T>
class InternalNode : public Node<T>
{
public:
    InternalNode(T *newData, Node<T> *newNode);
    virtual ~InternalNode()
    {
        delete data;
        delete next;
    };
    virtual Node<T> *insert(T *data);
    virtual void show()
    {
        std::cout << "- InternalNode show: \n";
        data->show();
        next->show();
    };

private:
    T *data;
    Node<T> *next;
};

template <class T>
InternalNode<T>::InternalNode(T *newData, Node<T> *newNode) : data(newData), next(newNode)
{
    std::cout << "Internal Node init \n";
}

template <class T>
Node<T> *InternalNode<T>::insert(T *otherdata)
{
    std::cout << "Internal node insert function called.\n";
    int result = data->compare(*otherdata);
    switch (result)
    {
    case kIsSame:
    case kIsLarger:
    {
        InternalNode<T> *dataNode = new InternalNode<T>(otherdata, this);
        return dataNode;
    }
    case kIsSmaller:
        next = next->insert(otherdata);
        return this;
    }
    
    return this;
}

// Tail Node:
template <class T>
class TailNode : public Node<T>
{
public:
    TailNode(){};
    virtual ~TailNode(){};
    virtual Node<T> *insert(T *data);
    virtual void show()
    {
        std::cout << "- TailNode show: \n";
    };

private:
};

template <class T>
Node<T> *TailNode<T>::insert(T *data)
{
    std::cout << ">";
    InternalNode<T> *dataNode = new InternalNode<T>(data, this);
    return dataNode;
}

// Head Node: 
template <class T>
class HeadNode : public Node<T>
{
public:
    HeadNode();
    virtual ~HeadNode() { delete next; };
    virtual Node<T> *insert(T *data);
    virtual void show() { 
        std::cout << "- HeadNode show: ";
        next->show(); };
private:
    Node<T> *next;
};

template <class T>
HeadNode<T>::HeadNode()
{
    next = new TailNode<T>;
}

template <class T>
Node<T> *HeadNode<T>::insert(T *data)
{
    next = next->insert(data);
    return this;
}

// Linked List:
template <class T>
class LinkedList
{
public:
    LinkedList();
    ~LinkedList(){delete head;};
    void insert(T *data);
    void showAll() { 
        std::cout << "linkedList show: ";
        head->show(); };

private:
    HeadNode<T> *head;
};

template <class T>
LinkedList<T>::LinkedList()
{
    head = new HeadNode<T>;
}

template <class T>
void LinkedList<T>::insert(T *pdata)
{
    head->insert(pdata);
}

//=============================================================================
/* Usage example: 
    Data *pdata;
    int val;
    LinkedList<Data> ll;
    while (true)
    {
        std::cout << "Input value(0 for stop):";
        std::cin >> val;
        if (!val)
            break;
        pdata = new Data(val);
        ll.insert(pdata);
    }

    std::cout << "Linked list:\n";
    ll.showAll();
*/