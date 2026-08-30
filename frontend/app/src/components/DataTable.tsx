import React from 'react';

export type DataTableColumn<Row> = {
  key: keyof Row;
  header: string;
  render?: (row: Row) => React.ReactNode;
};

export function DataTable<Row extends { id: string }>({
  caption,
  columns,
  rows,
}: {
  caption: string;
  columns: readonly DataTableColumn<Row>[];
  rows: readonly Row[];
}) {
  return (
    <div className="table-scroll" tabIndex={0}>
      <table>
        <caption>{caption}</caption>
        <thead>
          <tr>{columns.map((column) => <th key={String(column.key)} scope="col">{column.header}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id}>
              {columns.map((column) => <td key={String(column.key)}>{column.render ? column.render(row) : String(row[column.key] ?? '')}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
