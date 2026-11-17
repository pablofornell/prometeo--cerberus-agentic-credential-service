import { useScreenT } from "../../../i18n";
import { Field, Select } from "../../../ui";
import { FIELDS, fieldMessage } from "./fields";
import { messages } from "./messages";

interface Props {
  columns: readonly string[];
  mapping: Record<string, string>;
  onChange: (next: Record<string, string>) => void;
  showRequired: boolean;
}

/** One select per item field: which column of the file feeds it. */
export function MappingTable({ columns, mapping, onChange, showRequired }: Props) {
  const tr = useScreenT(messages);
  const options = [{ value: "", label: tr("imp.map.none") }, ...columns.filter((c) => c !== "").map((c) => ({ value: c, label: c }))];
  return (
    <fieldset className="csv-map">
      <legend>{tr("imp.map.title")}</legend>
      <p className="hint">{tr("imp.map.hint")}</p>
      <div className="csv-map-grid">
        {FIELDS.map((field) => (
          <Field key={field} label={tr(fieldMessage(field))} problem={field === "title" && showRequired ? tr("imp.map.required") : undefined}>
            {(p) => (
              <Select
                {...p}
                value={mapping[field] ?? ""}
                options={options}
                onChange={(e) => {
                  const next = { ...mapping };
                  if (e.target.value === "") delete next[field];
                  else next[field] = e.target.value;
                  onChange(next);
                }}
              />
            )}
          </Field>
        ))}
      </div>
    </fieldset>
  );
}
