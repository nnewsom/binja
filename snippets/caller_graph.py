#
#
def node_lines( function , external=False ):
    token_type = InstructionTextTokenType.CodeSymbolToken
    if external:
        token_type = InstructionTextTokenType.ExternalSymbolToken

    tokens = [
        InstructionTextToken(
            token_type,
            function.name,
            function.start
        ),
        InstructionTextToken(
            InstructionTextTokenType.OperandSeparatorToken, " @ "
        ),
        InstructionTextToken(
            InstructionTextTokenType.PossibleAddressToken,
            "{:#x}".format( function.start),
            value = function.start,
            address = function.start,
        ), 
    ]

    lines = [
        DisassemblyTextLine( tokens )
    ]
    return lines

def create_node( graph, func ):
    node = binaryninja.FlowGraphNode( graph )
    if func.symbol.type == SymbolType.FunctionSymbol:
        node.lines = node_lines( func )
    else:
        node.lines = node_lines( func, external=True )
    return node

def iterative_callers( graph, start_func ):
    root_node  = create_node( graph, start_func )
    graph.append( root_node )
    stack = [ ( root_node, set(), start_func ) ]

    while stack:
        parent_node, history, func = stack.pop()
        if func in history:
            continue

        history.add( func )
        for caller in set( func.callers ):
            child_node = create_node( graph, caller )
            graph.append( child_node )
            parent_node.add_outgoing_edge(
                BranchType.UnconditionalBranch,
                child_node
            )
            stack.append( ( child_node, history, caller ) )
        
graph = binaryninja.FlowGraph()
graph.function = bv.get_function_at(bv.entry_point)

if current_function != None:
    iterative_callers( graph, current_function )
    show_graph_report( 
        "{} callees".format( current_function.name ),
        graph
    )
else:
    log_error("no current function selected")