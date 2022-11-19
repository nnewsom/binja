class Visitor(object):
    def __init__(self, bv, function ):
        self.bv = bv
        self.function = function
        self.imports = set()

        self.handlers = {}
        for e in HighLevelILOperation:
            self.handlers[ e.value ] = self.__generic_visit

        self.handlers[ HighLevelILOperation.HLIL_CALL ] = \
                                        self.__visit_HLIL_CALL
        self.handlers[ HighLevelILOperation.HLIL_TAILCALL ] = \
                                        self.__visit_HLIL_CALL

    def __generic_visit( self, node ):
        for x in node.operands:
            self.visit( x )

    def __visit_HLIL_CALL( self, node ):
        if isinstance( node.dest, HighLevelILImport ):
            addr = node.dest.constant
            symbol = self.bv.get_symbol_at( addr )
            self.imports.add( symbol )

    def visit( self, node ):
        if node is None:
            return None
        elif isinstance( node, HighLevelILInstruction ):
            return self.handlers[ node.operation ]( node )
        else:
            return None

    def walk(self):
        for block in self.function.hlil:
            for instr in block:
                self.visit( instr )

def get_import_callees( bv, function ):
    v = Visitor( bv, function )
    v.walk()
    return v.imports

def node_lines( name, addr , external=False ):
    token_type = InstructionTextTokenType.CodeSymbolToken
    if external:
        token_type = InstructionTextTokenType.ExternalSymbolToken

    tokens = [
        InstructionTextToken(
            token_type,
            name,
            addr
        ),
        InstructionTextToken(
            InstructionTextTokenType.OperandSeparatorToken, " @ "
        ),
        InstructionTextToken(
            InstructionTextTokenType.PossibleAddressToken,
            "{:#x}".format( addr ),
            value = addr,
            address = addr,
        ), 
    ]

    lines = [
        DisassemblyTextLine( tokens )
    ]
    return lines

def create_node( graph, name, addr, stype ):
    node = binaryninja.FlowGraphNode( graph )
    if stype == SymbolType.FunctionSymbol:
        node.lines = node_lines( name, addr )
    else:
        node.lines = node_lines( name, addr, external=True )
    return node

def iterative_callee( bv, graph, start_func ):
    root_node  = create_node( 
                    graph,
                    start_func.name,
                    start_func.start,
                    start_func.symbol.type
                )
    graph.append( root_node )
    stack = [ ( root_node, set(), start_func ) ]

    while stack:
        parent_node, history, func = stack.pop()
        if func in history:
            # log_info(f"{func.name} in history")
            continue

        history.add( func )
        imports = get_import_callees( bv, func )
        for symbol in imports:
            # log_info(f"import: {func.name}->{symbol.name}")
            child_node = create_node( 
                            graph,
                            symbol.name,
                            symbol.address,
                            symbol.type
                        )
            graph.append( child_node )
            parent_node.add_outgoing_edge(
                BranchType.UnconditionalBranch,
                child_node
            )

        for callee in set( func.callees ):
            # log_info(f"callee: {func.name}->{callee.name}")
            child_node = create_node( 
                            graph,
                            callee.name,
                            callee.start,
                            callee.symbol.type
                        )
            graph.append( child_node )
            parent_node.add_outgoing_edge(
                BranchType.UnconditionalBranch,
                child_node
            )
            if callee.symbol.type == SymbolType.FunctionSymbol:
                stack.append( ( child_node, history, callee ) )
        
graph = binaryninja.FlowGraph()
graph.function = bv.get_function_at(bv.entry_point)

if current_function != None:
    iterative_callee( bv, graph, current_function )
    show_graph_report( 
        f"{ current_function.name } callees",
        graph
    )
else:
    log_error("no current function selected")
