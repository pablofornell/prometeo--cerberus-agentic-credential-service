import { useScreenT } from "../../i18n";
import { messages } from "./messages";
import { Wizard } from "./Wizard";
import "./create.css";

/** Screen 1: create the vault. The route guard shows it only while no vault exists. */
export default function CreateScreen() {
  const t = useScreenT(messages);
  return (
    <section aria-label={t("name.title")} data-screen="create" className="create-screen guilloche">
      <Wizard />
    </section>
  );
}
