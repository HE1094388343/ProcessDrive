
#include"VadHelpers.h"



TABLE_SEARCH_RESULT
MiFindNodeOrParent(
    IN PMM_AVL_TABLE Table,
    IN ULONG_PTR StartingVpn,
    OUT PMMADDRESS_NODE* NodeOrParent
)
{

    PMMADDRESS_NODE Child;
    PMMADDRESS_NODE NodeToExamine;
    PMMVAD_SHORT    VpnCompare;
    ULONG_PTR       startVpn;
    ULONG_PTR       endVpn;

    if (Table->NumberGenericTableElements == 0) {
        return TableEmptyTree;
    }

    NodeToExamine = (PMMADDRESS_NODE)GET_VAD_ROOT(Table);

    for (;;) {

        VpnCompare = (PMMVAD_SHORT)NodeToExamine;
        startVpn = VpnCompare->StartingVpn;
        endVpn = VpnCompare->EndingVpn;

#if defined( _WIN81_ ) || defined( _WIN10_ )
        startVpn |= (ULONG_PTR)VpnCompare->StartingVpnHigh << 32;
        endVpn |= (ULONG_PTR)VpnCompare->EndingVpnHigh << 32;
#endif  

        //
        // Compare the buffer with the key in the tree element.
        //

        if (StartingVpn < startVpn) {

            Child = NodeToExamine->LeftChild;

            if (Child != NULL) {
                NodeToExamine = Child;
            }
            else {

                //
                // Node is not in the tree.  Set the output
                // parameter to point to what would be its
                // parent and return which child it would be.
                //

                *NodeOrParent = NodeToExamine;
                return TableInsertAsLeft;
            }
        }
        else if (StartingVpn <= endVpn) {

            //
            // This is the node.
            //

            *NodeOrParent = NodeToExamine;
            return TableFoundNode;
        }
        else {

            Child = NodeToExamine->RightChild;

            if (Child != NULL) {
                NodeToExamine = Child;
            }
            else {

                //
                // Node is not in the tree.  Set the output
                // parameter to point to what would be its
                // parent and return which child it would be.
                //

                *NodeOrParent = NodeToExamine;
                return TableInsertAsRight;
            }
        }

    };

}