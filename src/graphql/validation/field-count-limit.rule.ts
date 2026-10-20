import {
  GraphQLError,
  Kind,
  type ASTVisitor,
  type FragmentDefinitionNode,
  type SelectionNode,
  type ValidationContext,
} from 'graphql';

/**
 * Maximum total field selections allowed per operation. Aliased
 * copies each count (N aliased `getUser` selections = N fields), so
 * this blunts alias-batching DoS where one HTTP request fans out
 * into hundreds of sequential resolver round-trips.
 */
export const GRAPHQL_MAX_FIELD_COUNT = 100;

/**
 * Custom validation rule capping the total field count per
 * operation (audit, GraphQL MEDIUM "no depth/alias/batch limits").
 *
 * Implemented as a standard graphql-js validation rule so it runs
 * inside Apollo's existing `validationRules` pipeline — no new
 * dependencies, no resolver involvement (rejected before execution).
 *
 * Fragment spreads are expanded inline per occurrence (with cycle
 * protection), so a fragment invoked 50 times contributes 50 times
 * its field count — exactly the amplification we want to count.
 */
export function createFieldCountLimitRule(
  maxFieldCount: number = GRAPHQL_MAX_FIELD_COUNT,
): (context: ValidationContext) => ASTVisitor {
  return (context: ValidationContext): ASTVisitor => {
    const fragments = new Map<string, FragmentDefinitionNode>();
    for (const def of context.getDocument().definitions) {
      if (def.kind === Kind.FRAGMENT_DEFINITION) {
        fragments.set(def.name.value, def);
      }
    }

    const countSelections = (
      selections: ReadonlyArray<SelectionNode>,
      activeFragments: ReadonlySet<string>,
    ): number => {
      let count = 0;
      for (const selection of selections) {
        if (selection.kind === Kind.FIELD) {
          count += 1;
          if (selection.selectionSet) {
            count += countSelections(
              selection.selectionSet.selections,
              activeFragments,
            );
          }
        } else if (selection.kind === Kind.INLINE_FRAGMENT) {
          if (selection.selectionSet) {
            count += countSelections(
              selection.selectionSet.selections,
              activeFragments,
            );
          }
        } else {
          // Fragment spread — expand it (cycle-guarded) so each
          // occurrence counts its own fields.
          const name = selection.name.value;
          if (activeFragments.has(name)) continue;
          const fragment = fragments.get(name);
          if (!fragment) continue;
          count += countSelections(
            fragment.selectionSet.selections,
            new Set([...activeFragments, name]),
          );
        }
      }
      return count;
    };

    return {
      OperationDefinition(node) {
        const total = countSelections(node.selectionSet.selections, new Set());
        if (total > maxFieldCount) {
          context.reportError(
            new GraphQLError(
              `Operation selects ${total} fields, exceeding the maximum of ${maxFieldCount} per operation.`,
              { nodes: [node] },
            ),
          );
        }
      },
    };
  };
}
