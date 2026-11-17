import type { ReactNode } from "react";
import { cx } from "./cx";

export interface Column<T> {
  id: string;
  header: string;
  cell: (row: T) => ReactNode;
  /** Right align and use tabular numbers. */
  numeric?: boolean;
}

interface DataTableProps<T> {
  /** Names the table for screen readers. It is not shown. */
  caption: string;
  columns: readonly Column<T>[];
  rows: readonly T[];
  rowKey: (row: T) => string;
  /** Rows become buttons-in-effect: Enter or click runs it. The first cell holds the real control. */
  onRowActivate?: (row: T) => void;
  selectedKey?: string | null;
}

/** A plain data table. For a list with rich rows use `RowList`. */
export function DataTable<T>({ caption, columns, rows, rowKey, onRowActivate, selectedKey }: DataTableProps<T>) {
  return (
    <table className="grid">
      <caption className="sr-only">{caption}</caption>
      <thead>
        <tr>
          {columns.map((c) => (
            <th key={c.id} scope="col" className={cx(c.numeric && "num right")}>
              {c.header}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => {
          const key = rowKey(row);
          return (
            <tr
              key={key}
              aria-selected={selectedKey === undefined ? undefined : selectedKey === key}
              onClick={onRowActivate ? () => onRowActivate(row) : undefined}
            >
              {columns.map((c) => (
                <td key={c.id} className={cx(c.numeric && "num right")}>
                  {c.cell(row)}
                </td>
              ))}
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

interface RowListProps<T> {
  label: string;
  rows: readonly T[];
  rowKey: (row: T) => string;
  /** One row: usually KindIcon, a `.grow` block with `.title` and `.sub`, then badges. */
  renderRow: (row: T) => ReactNode;
}

/** `ul.rows`: icon, title and context, then badges (agent-made, TTL ring, role chip, env badge rightmost). */
export function RowList<T>({ label, rows, rowKey, renderRow }: RowListProps<T>) {
  return (
    <ul className="rows" aria-label={label}>
      {rows.map((row) => (
        <li key={rowKey(row)}>{renderRow(row)}</li>
      ))}
    </ul>
  );
}
