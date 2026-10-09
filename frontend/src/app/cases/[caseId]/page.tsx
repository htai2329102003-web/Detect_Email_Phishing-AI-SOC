import { CaseWorkspace } from "../../../components/cases/CaseWorkspace";

type CasePageProps = {
  params: Promise<{ caseId: string }>;
};

export default async function CasePage({ params }: CasePageProps) {
  const { caseId } = await params;
  return <CaseWorkspace caseId={caseId} />;
}
