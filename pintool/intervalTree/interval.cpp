#include "interval.H"

// Driver program to test above functions

void search(ITNode *root, DTYPE low, DTYPE high)
{
		Interval x = {low, high, 0, true};

		std::cout << "\nSearching for interval [" << x.low << "," << x.high << "]";

		Interval *res = IT_overlapSearch(root, x);

		if (res == NULL)
				std::cout << "\nNo Overlapping Interval" << std::endl;
		else
				std::cout << "\nOverlaps with [" << res->low << ", " << res->high << "]" << std::endl;


}

void insert(ITNode *root, DTYPE low, DTYPE high, int id)
{
		std::cout << "Insert new interval [" << low << ", " << high << "]" << std::endl;
		Interval t = {low,high, id, true};
		root = IT_insert(root, t);

}

int main()
{
		// Let us create interval tree shown in above figure
		Interval ints[] = {{15, 20, 1, true}, {10, 30,2, true}, {17, 19,3, true},
				{5, 20,4, true}, {12, 15,5, true}, {30, 40,6, true}
		};
		int n = sizeof(ints)/sizeof(ints[0]);
		ITNode *root = NULL;
		for (int i = 0; i < n; i++)
				root = IT_insert(root, ints[i]);

		std::cout << "Inorder traversal of constructed Interval Tree is\n";
		IT_inorder(root);

		search(root, 105, 106);

		insert(root, 100, 110, 10);

		search(root, 105, 106);
		insert(root, 100, 109, 11);

		search(root, 105, 106);

		IT_inorder(root);
		IT_erase(root, 100);

		search(root, 105, 106);
		IT_inorder(root);
		return 0;
}

