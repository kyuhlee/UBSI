#include <iostream>
 
#define DTYPE long int
// Structure to represent an interval
struct Interval
{
    DTYPE low, high;
				DTYPE id;
				bool active;
};
 
// Structure to represent a node in Interval Search Tree
struct ITNode
{
    Interval *i;  // 'i' could also be a normal variable
    DTYPE max;
    ITNode *left, *right;
};
 
// A utility function to create a new Interval Search Tree Node
ITNode * IT_newNode(Interval i)
{
    ITNode *temp = new ITNode;
    temp->i = new Interval(i);
    temp->max = i.high;
    temp->left = temp->right = NULL;

				return temp;
};
 
// A utility function to insert a new Interval Search Tree Node
// This is similar to BST Insert.  Here the low value of interval
// is used tomaintain BST property
ITNode *IT_insert(ITNode *root, Interval i)
{
    // Base case: Tree is empty, new node becomes root
    if (root == NULL)
        return IT_newNode(i);
 
    // Get low value of interval at root
    DTYPE l = root->i->low;
 
    // If root's low value is smaller, then new interval goes to
    // left subtree
    if (i.low < l)
        root->left = IT_insert(root->left, i);
 
    // Else, new node goes to right subtree.
    else
        root->right = IT_insert(root->right, i);
 
    // Update the max value of this ancestor if needed
    if (root->max < i.high)
        root->max = i.high;
 
    return root;
}
 
// A utility function to check if given two intervals overlap
bool IT_doOVerlap(Interval i1, Interval i2)
{
    if (i1.low <= i2.high && i2.low <= i1.high && i1.active)
        return true;
    return false;
}
 
// The main function that searches a given interval i in a given
// Interval Tree.
Interval *IT_overlapSearch(ITNode *root, Interval i)
{
    // Base Case, tree is empty
    if (root == NULL) return NULL;
 
    // If given interval overlaps with root
    if (IT_doOVerlap(*(root->i), i))
        return root->i;
 
    // If left child of root is present and max of left child is
    // greater than or equal to given interval, then i may
    // overlap with an interval is left subtree
    if (root->left != NULL && root->left->max >= i.low)
        return IT_overlapSearch(root->left, i);
 
    // Else interval can only overlap with right subtree
    return IT_overlapSearch(root->right, i);
}

bool IT_matchLow(Interval i1, DTYPE low)
{
    if (i1.low == low && i1.active)
        return true;
    return false;
}

// The main function that searches a given interval i in a given
// Interval Tree.
Interval *IT_eraseSearch(ITNode *root, DTYPE low)
{
    // Base Case, tree is empty
    if (root == NULL) return NULL;

    // If given interval overlaps with root
    if (IT_matchLow(*(root->i), low))
        return root->i;

    // If left child of root is present and max of left child is
    // greater than or equal to given interval, then i may
    // overlap with an interval is left subtree
    if (root->left != NULL && root->left->max >= low)
        return IT_eraseSearch(root->left, low);

    // Else interval can only overlap with right subtree
    return IT_eraseSearch(root->right, low);
}

bool IT_erase(ITNode *root, DTYPE low)
{
  bool ret = false;
  Interval *res;
  while((res = IT_eraseSearch(root, low)) != NULL)
  {
    res->active = false;
    ret = true;
  }
  return ret;
}

void IT_inorder(ITNode *root)
{
    if (root == NULL) return;
				std::cout << "IT_Inorder:" << std::endl;
 
    IT_inorder(root->left);
 
    if(root->i->active) std::cout << "[0x" << std::hex << root->i->low << ", 0x" << root->i->high << "]"
         << " max = " << root->max << std::dec << std::endl;
 
    IT_inorder(root->right);
}
 

