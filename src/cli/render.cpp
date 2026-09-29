// Copyright 2026 Summon Software Labs
// SPDX-License-Identifier: Apache-2.0

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "cli.hpp"

namespace decommissioning_fabric::cli {
namespace {

[[nodiscard]] std::string Line(std::string_view key, std::string_view value) {
  std::string out("  ");
  out.append(key);
  out.append(": ");
  out.append(value);
  out.push_back('\n');
  return out;
}

[[nodiscard]] std::string HexValue(std::uint64_t value) {
  return detail::to_hex_fixed(value, 16);
}

[[nodiscard]] std::string GenerationText(std::uint32_t value) {
  return std::to_string(value);
}

void AddAuthority(JsonWriter& json, const AuthorityReport& report) {
  json.BeginArray("authority");
  for (const DomainAssessment& assessment : report.domains) {
    json.BeginObject();
    json.Field("domain", ToString(assessment.domain));
    json.Field("status", ToString(assessment.status));
    json.Field("covering_receipt",
               assessment.covering_receipt.is_set() ? assessment.covering_receipt.to_hex()
                                                    : std::string("none"));
    json.Field("stale_receipt_present", assessment.stale_receipt_present);
    json.EndObject();
  }
  json.EndArray();
}

}  // namespace

std::string RenderDecision(const Decision& decision, bool json) {
  if (json) {
    std::string out;
    JsonWriter writer(out);
    writer.BeginObject();
    writer.Field("applied", decision.applied);
    writer.Field("replayed", decision.replayed);
    writer.Field("kind", ToString(decision.kind));
    writer.Field("plan", decision.plan.is_set() ? decision.plan.to_hex() : std::string(""));
    writer.Field("asset", decision.asset.is_set() ? decision.asset.to_hex() : std::string(""));
    writer.Field("lifecycle_generation",
                 static_cast<std::uint64_t>(decision.lifecycle_generation.value()));
    writer.Field("from_phase", ToString(decision.from_phase));
    writer.Field("to_phase", ToString(decision.to_phase));
    writer.Field("revision", decision.revision.value());
    writer.Field("committed_sequence", decision.committed_sequence.value());
    writer.Field("idempotency_key", decision.key.to_hex());
    writer.BeginArray("effects");
    for (const ErrorDetail& effect : decision.effects) {
      writer.BeginObject();
      writer.Field(effect.key, effect.value);
      writer.EndObject();
    }
    writer.EndArray();
    writer.BeginArray("notes");
    for (const RecordedNote& note : decision.notes) {
      writer.BeginObject();
      writer.Field("code", note.code);
      writer.Field("text", note.text);
      writer.EndObject();
    }
    writer.EndArray();
    writer.EndObject();
    out.push_back('\n');
    return out;
  }

  std::string out;
  out += "decision\n";
  out += Line("applied", decision.applied ? "true" : "false");
  out += Line("replayed", decision.replayed ? "true" : "false");
  out += Line("kind", ToString(decision.kind));
  out += Line("plan", decision.plan.is_set() ? decision.plan.to_hex() : "(none)");
  out += Line("asset", decision.asset.is_set() ? decision.asset.to_hex() : "(none)");
  out += Line("lifecycle_generation",
              std::to_string(decision.lifecycle_generation.value()));
  if (decision.kind != RequestKind::unknown) {
    out += Line("phase", std::string(ToString(decision.from_phase)) + " -> " +
                             std::string(ToString(decision.to_phase)));
  }
  out += Line("revision", std::to_string(decision.revision.value()));
  out += Line("committed_sequence", std::to_string(decision.committed_sequence.value()));
  out += Line("idempotency_key", decision.key.to_hex());
  for (const ErrorDetail& effect : decision.effects) {
    out += Line("  " + effect.key, effect.value);
  }
  for (const RecordedNote& note : decision.notes) {
    out += Line(std::string("note/") + note.code, note.text);
  }
  return out;
}

std::string RenderError(const Error& error, bool json) {
  if (json) {
    std::string out;
    JsonWriter writer(out);
    writer.BeginObject();
    writer.Field("ok", false);
    writer.Field("stage", ToString(error.stage));
    writer.Field("code", ToString(error.code));
    writer.Field("message", error.message);
    writer.BeginArray("details");
    for (const ErrorDetail& detail : error.details) {
      writer.BeginObject();
      writer.Field(detail.key, detail.value);
      writer.EndObject();
    }
    writer.EndArray();
    writer.EndObject();
    out.push_back('\n');
    return out;
  }
  std::string out;
  out += "refused\n";
  out += Line("stage", ToString(error.stage));
  out += Line("code", ToString(error.code));
  out += Line("message", error.message);
  for (const ErrorDetail& detail : error.details) {
    out += Line(std::string("  ") + detail.key, detail.value);
  }
  return out;
}

std::string RenderAsset(const AssetView& view, bool json) {
  if (json) {
    std::string out;
    JsonWriter writer(out);
    writer.BeginObject();
    writer.Field("asset", view.asset.id.to_hex());
    writer.Field("site", view.asset.site.to_hex());
    writer.Field("rack", view.asset.rack.to_hex());
    writer.Field("hardware_generation", view.asset.hardware_generation.value());
    writer.Field("firmware_generation", view.asset.firmware_generation.value());
    writer.Field("lifecycle_generation", view.asset.lifecycle_generation.value());
    writer.Field("authority_mask", view.asset.active_authority.bits);
    writer.Field("present", view.asset.present);
    writer.Field("model", view.asset.model);
    writer.Field("serial", view.asset.serial);
    writer.Field("current_plan", view.asset.current_plan.to_hex());
    writer.Field("has_case", view.has_case);
    if (view.has_case) {
      writer.Field("case_generation", view.case_key.generation.value());
      writer.Field("phase", ToString(view.phase));
    }
    writer.EndObject();
    out.push_back('\n');
    return out;
  }
  std::string out;
  out += "asset\n";
  out += Line("asset", view.asset.id.to_hex());
  out += Line("site", view.asset.site.to_hex());
  out += Line("rack", view.asset.rack.to_hex());
  out += Line("hardware_generation", GenerationText(view.asset.hardware_generation.value()));
  out += Line("firmware_generation", GenerationText(view.asset.firmware_generation.value()));
  out += Line("lifecycle_generation", GenerationText(view.asset.lifecycle_generation.value()));
  out += Line("authority_mask", HexValue(view.asset.active_authority.bits));
  out += Line("active_domains", std::to_string(view.asset.active_authority.count()));
  out += Line("present", view.asset.present ? "true" : "false");
  if (!view.asset.model.empty()) {
    out += Line("model", view.asset.model);
  }
  if (!view.asset.serial.empty()) {
    out += Line("serial", view.asset.serial);
  }
  out += Line("current_plan",
              view.asset.current_plan.is_set() ? view.asset.current_plan.to_hex() : "(none)");
  out += Line("phase", view.has_case ? std::string(ToString(view.phase)) : "(no case)");
  return out;
}

std::string RenderAuthority(const AuthorityReport& report, bool json) {
  if (json) {
    std::string out;
    JsonWriter writer(out);
    writer.BeginObject();
    writer.Field("active_count", static_cast<std::uint64_t>(report.active_count));
    writer.Field("revoked_count", static_cast<std::uint64_t>(report.revoked_count));
    writer.Field("unknown_count", static_cast<std::uint64_t>(report.unknown_count));
    writer.Field("fully_revoked", report.fully_revoked());
    AddAuthority(writer, report);
    writer.EndObject();
    out.push_back('\n');
    return out;
  }
  std::string out;
  out += "authority\n";
  for (const DomainAssessment& assessment : report.domains) {
    std::string detail(ToString(assessment.domain));
    detail += " = ";
    detail += ToString(assessment.status);
    if (assessment.covering_receipt.is_set()) {
      detail += " (receipt ";
      detail += assessment.covering_receipt.to_hex();
      detail += ")";
    }
    if (assessment.stale_receipt_present) {
      detail += " [a receipt exists under a superseded binding]";
    }
    out += Line("  ", detail);
  }
  out += Line("active", std::to_string(report.active_count));
  out += Line("revoked", std::to_string(report.revoked_count));
  out += Line("unknown", std::to_string(report.unknown_count));
  out += Line("fully_revoked", report.fully_revoked() ? "true" : "false");
  return out;
}

std::string RenderCase(const CaseView& view, bool json) {
  const RetirementCase& record = view.record;
  if (json) {
    std::string out;
    JsonWriter writer(out);
    writer.BeginObject();
    writer.Field("asset", record.key.asset.to_hex());
    writer.Field("lifecycle_generation", record.key.generation.value());
    writer.Field("plan", record.plan.to_hex());
    writer.Field("phase", ToString(record.phase));
    writer.Field("resume_phase", ToString(record.resume_phase));
    writer.Field("revision", record.fence.revision.value());
    writer.Field("fence_token", view.fence_token);
    writer.Field("facility_epoch", record.fence.facility_epoch.value());
    writer.Field("policy_generation", record.fence.policy_generation.value());
    writer.Field("dependency_generation", record.fence.dependency_generation.value());
    writer.Field("hardware_generation", record.fence.hardware_generation.value());
    writer.Field("firmware_generation", record.fence.firmware_generation.value());
    writer.Field("active_obligation_count", record.fence.active_obligation_count);
    writer.Field("active_obligation_digest", record.fence.active_obligation_digest.to_hex());
    writer.Field("isolation_observed", record.isolation_observed);
    writer.Field("removal_authorized", record.removal_authorized);
    writer.Field("removal_observed", record.removal.observed);
    writer.Field("canonical_deletion", record.removal.canonical_deletion);
    writer.Field("cancel_reason", record.cancel_reason);
    writer.Field("failure_reason", record.failure_reason);
    writer.Field("blocker_reason", ToString(record.blocker.reason));
    writer.Field("blocker_detail", record.blocker.detail);
    writer.Field("blocker_required_action", record.blocker.required_action);

    writer.BeginArray("obligations");
    for (const DrainObligation& obligation : record.obligations) {
      writer.BeginObject();
      writer.Field("obligation", obligation.id.to_hex());
      writer.Field("kind", ToString(obligation.kind));
      writer.Field("state", ToString(obligation.state));
      writer.Field("protected_class", ToString(obligation.protected_class));
      writer.Field("required", obligation.required);
      writer.Field("issued_to", obligation.issued_to);
      writer.Field("issued_sequence", obligation.issued_sequence.value());
      writer.Field("satisfied_by", obligation.satisfied_by);
      writer.Field("blocks_progress", obligation.blocks_progress());
      writer.EndObject();
    }
    writer.EndArray();

    writer.BeginArray("residual");
    for (const ResidualItem& item : record.residual) {
      writer.BeginObject();
      writer.Field("item", item.id.to_hex());
      writer.Field("category", ToString(item.category));
      writer.Field("disposition", ToString(item.disposition));
      writer.Field("authority", item.authority);
      writer.Field("reference", item.reference);
      writer.Field("waiver", item.waiver.is_set() ? item.waiver.to_hex() : std::string(""));
      writer.EndObject();
    }
    writer.EndArray();

    writer.BeginArray("exceptions");
    for (const PolicyException& exception : record.exceptions) {
      writer.BeginObject();
      writer.Field("exception", exception.id.to_hex());
      writer.Field("item", exception.item.to_hex());
      writer.Field("obligation", exception.obligation.to_hex());
      writer.Field("authority", exception.authority);
      writer.Field("reference", exception.reference);
      writer.Field("rationale", exception.rationale);
      writer.EndObject();
    }
    writer.EndArray();

    writer.BeginArray("evidence");
    for (const EvidenceRef& evidence : record.evidence) {
      writer.BeginObject();
      writer.Field("evidence", evidence.id.to_hex());
      writer.Field("kind", ToString(evidence.kind));
      writer.Field("provenance", ToString(evidence.provenance));
      writer.Field("freshness", ToString(evidence.freshness));
      writer.Field("observer", evidence.observer);
      writer.Field("reference", evidence.reference);
      writer.Field("observation_sequence", evidence.observation_sequence.value());
      writer.EndObject();
    }
    writer.EndArray();

    writer.BeginArray("receipts");
    for (const RevocationReceipt& receipt : record.receipts) {
      writer.BeginObject();
      writer.Field("receipt", receipt.id.to_hex());
      writer.Field("domain", ToString(receipt.domain));
      writer.Field("authority", receipt.authority);
      writer.Field("reference", receipt.reference);
      writer.Field("observation_sequence", receipt.observation_sequence.value());
      writer.EndObject();
    }
    writer.EndArray();

    writer.BeginArray("notes");
    for (const RecordedNote& note : record.notes) {
      writer.BeginObject();
      writer.Field("code", note.code);
      writer.Field("text", note.text);
      writer.EndObject();
    }
    writer.EndArray();

    writer.Field("active_count", static_cast<std::uint64_t>(view.authority.active_count));
    writer.Field("revoked_count", static_cast<std::uint64_t>(view.authority.revoked_count));
    writer.Field("unknown_count", static_cast<std::uint64_t>(view.authority.unknown_count));
    writer.Field("authority_fully_revoked", view.authority.fully_revoked());
    AddAuthority(writer, view.authority);
    writer.EndObject();
    out.push_back('\n');
    return out;
  }

  std::string out;
  out += "retirement case\n";
  out += Line("asset", record.key.asset.to_hex());
  out += Line("lifecycle_generation", std::to_string(record.key.generation.value()));
  out += Line("plan", record.plan.to_hex());
  out += Line("phase", ToString(record.phase));
  if (record.phase == Phase::blocked) {
    out += Line("resume_phase", ToString(record.resume_phase));
  }
  out += Line("revision", std::to_string(record.fence.revision.value()));
  out += Line("fence_token", view.fence_token);
  out += Line("facility_epoch", std::to_string(record.fence.facility_epoch.value()));
  out += Line("policy_generation", std::to_string(record.fence.policy_generation.value()));
  out += Line("dependency_generation", std::to_string(record.fence.dependency_generation.value()));
  out += Line("active_obligations",
              std::to_string(record.fence.active_obligation_count) + " digest=" +
                  record.fence.active_obligation_digest.to_hex());
  if (record.blocker.is_set()) {
    out += Line("blocker", record.blocker.to_string());
  }
  if (!record.cancel_reason.empty()) {
    out += Line("cancel_reason", record.cancel_reason);
  }
  if (!record.failure_reason.empty()) {
    out += Line("failure_reason", record.failure_reason);
  }

  out += "\nobligations\n";
  if (record.obligations.empty()) {
    out += "  (none)\n";
  }
  for (const DrainObligation& obligation : record.obligations) {
    std::string detail = obligation.id.to_hex();
    detail += "  ";
    detail += ToString(obligation.kind);
    detail += "  state=";
    detail += ToString(obligation.state);
    if (obligation.is_protected()) {
      detail += "  protected=";
      detail += ToString(obligation.protected_class);
    }
    if (!obligation.required) {
      detail += "  optional";
    }
    if (!obligation.issued_to.empty()) {
      detail += "  issued_to=";
      detail += obligation.issued_to;
    }
    if (obligation.blocks_progress()) {
      detail += "  [blocking]";
    }
    out += Line("  ", detail);
  }

  out += "\nresidual checklist\n";
  if (record.residual.empty()) {
    out += "  (none recorded; an unrecorded category is not an absent one)\n";
  }
  for (const ResidualItem& item : record.residual) {
    std::string detail = item.id.to_hex();
    detail += "  ";
    detail += ToString(item.category);
    detail += "  disposition=";
    detail += ToString(item.disposition);
    if (!item.authority.empty()) {
      detail += "  authority=";
      detail += item.authority;
    }
    if (item.waiver.is_set()) {
      detail += "  exception=";
      detail += item.waiver.to_hex();
    }
    out += Line("  ", detail);
  }

  if (!record.exceptions.empty()) {
    out += "\npolicy exceptions\n";
    for (const PolicyException& exception : record.exceptions) {
      std::string detail = exception.id.to_hex();
      detail += "  authority=";
      detail += exception.authority;
      detail += "  reference=";
      detail += exception.reference;
      detail += "  rationale=";
      detail += exception.rationale;
      out += Line("  ", detail);
    }
  }

  out += "\nremoval\n";
  out += Line("  isolation_observed", record.isolation_observed ? "true" : "false");
  if (record.isolation_observed) {
    out += Line("    observer", record.isolation_observer);
    out += Line("    reference", record.isolation_reference);
  }
  out += Line("  removal_authorized", record.removal_authorized ? "true" : "false");
  if (record.removal_authorized) {
    out += Line("    authority", record.removal_authority);
    out += Line("    reference", record.removal_authorization_reference);
  }
  out += Line("  removal_observed", record.removal.observed ? "true" : "false");
  if (record.removal.observed) {
    out += Line("    observer", record.removal.observer);
    out += Line("    reference", record.removal.reference);
  }
  out += Line("  canonical_deletion",
              "false (owned by the inventory system, never claimed here)");

  out += "\n";
  out += RenderAuthority(view.authority, false);

  out += "\nevidence\n";
  if (record.evidence.empty()) {
    out += "  (none)\n";
  }
  for (const EvidenceRef& evidence : record.evidence) {
    std::string detail = evidence.id.to_hex();
    detail += "  ";
    detail += ToString(evidence.kind);
    detail += "  ";
    detail += ToString(evidence.freshness);
    detail += "  observer=";
    detail += evidence.observer;
    detail += "  reference=";
    detail += evidence.reference;
    out += Line("  ", detail);
  }

  out += "\nnotes\n";
  for (const RecordedNote& note : record.notes) {
    out += Line("  " + note.code, note.text);
  }
  return out;
}

std::string RenderBlockers(const BlockerReport& report, bool json) {
  if (json) {
    std::string out;
    JsonWriter writer(out);
    writer.BeginObject();
    writer.Field("asset", report.key.asset.to_hex());
    writer.Field("lifecycle_generation", report.key.generation.value());
    writer.Field("plan", report.plan.to_hex());
    writer.Field("phase", ToString(report.phase));
    writer.Field("resume_phase", ToString(report.resume_phase));
    writer.Field("next_phase", ToString(report.next_phase));
    writer.Field("ready_to_advance", report.ready_to_advance);
    writer.Field("next_action", report.next_action);
    writer.Field("total_obligations", static_cast<std::uint64_t>(report.total_obligations));
    writer.Field("open_obligations", static_cast<std::uint64_t>(report.open_obligations));
    writer.Field("total_residual", static_cast<std::uint64_t>(report.total_residual));
    writer.Field("unresolved_residual", static_cast<std::uint64_t>(report.unresolved_residual));
    writer.Field("unknown_residual", static_cast<std::uint64_t>(report.unknown_residual));
    writer.BeginArray("blockers");
    for (const Blocker& blocker : report.blockers) {
      writer.BeginObject();
      writer.Field("reason", ToString(blocker.reason));
      writer.Field("code", ToString(blocker.code));
      writer.Field("detail", blocker.detail);
      writer.Field("required_action", blocker.required_action);
      writer.BeginArray("observed");
      for (const ErrorDetail& detail : blocker.observed) {
        writer.BeginObject();
        writer.Field(detail.key, detail.value);
        writer.EndObject();
      }
      writer.EndArray();
      writer.EndObject();
    }
    writer.EndArray();
    AddAuthority(writer, report.authority);
    writer.EndObject();
    out.push_back('\n');
    return out;
  }

  std::string out;
  out += "blocker explanation\n";
  out += Line("asset", report.key.asset.to_hex());
  out += Line("lifecycle_generation", std::to_string(report.key.generation.value()));
  out += Line("plan", report.plan.to_hex());
  out += Line("phase", ToString(report.phase));
  if (report.phase == Phase::blocked) {
    out += Line("resume_phase", ToString(report.resume_phase));
  }
  out += Line("next_phase", ToString(report.next_phase));
  out += Line("ready_to_advance", report.ready_to_advance ? "true" : "false");
  out += Line("next_action", report.next_action);
  out += Line("obligations", std::to_string(report.open_obligations) + " open of " +
                                   std::to_string(report.total_obligations));
  out += Line("residual", std::to_string(report.unresolved_residual) + " unresolved of " +
                              std::to_string(report.total_residual) + " (" +
                              std::to_string(report.unknown_residual) + " unknown)");
  out += "\n";
  if (report.blockers.empty()) {
    out += "  no blockers: this plan may advance\n";
  }
  for (std::size_t index = 0; index < report.blockers.size(); ++index) {
    const Blocker& blocker = report.blockers[index];
    out += Line("blocker " + std::to_string(index + 1), std::string(ToString(blocker.reason)) +
                                                           " (" + std::string(ToString(blocker.code)) +
                                                           ")");
    out += Line("  detail", blocker.detail);
    for (const ErrorDetail& detail : blocker.observed) {
      out += Line(std::string("    ") + detail.key, detail.value);
    }
    out += Line("  required", blocker.required_action);
  }
  out += "\n";
  out += RenderAuthority(report.authority, false);
  return out;
}

std::string RenderRecovery(const std::string& directory, const RecoveryReport& report,
                           CommitSequence sequence, bool json) {
  if (json) {
    std::string out;
    JsonWriter writer(out);
    writer.BeginObject();
    writer.Field("directory", directory);
    writer.Field("sequence", sequence.value());
    writer.Field("fresh", report.fresh);
    writer.Field("unrecoverable", report.unrecoverable);
    writer.Field("recovered_from_slot_b", report.recovered_from_slot_b);
    writer.Field("recovered_sequence", report.recovered_sequence.value());
    writer.Field("slot_a_status", ToString(report.slot_a.status));
    writer.Field("slot_b_status", ToString(report.slot_b.status));
    writer.Field("slot_a_sequence", report.slot_a.sequence.value());
    writer.Field("slot_b_sequence", report.slot_b.sequence.value());
    writer.BeginArray("torn_slots");
    for (const std::string& torn : report.torn_slots) {
      writer.Value(torn);
    }
    writer.EndArray();
    writer.EndObject();
    out.push_back('\n');
    return out;
  }
  std::string out;
  out += "store\n";
  out += Line("directory", directory);
  out += Line("sequence", std::to_string(sequence.value()));
  out += Line("fresh", report.fresh ? "true" : "false");
  out += Line("recovered_sequence", std::to_string(report.recovered_sequence.value()));
  out += Line("recovered_slot", report.recovered_from_slot_b ? "state.b" : "state.a");
  out += Line("slot_a",
              std::string(ToString(report.slot_a.status)) + " sequence=" +
                  std::to_string(report.slot_a.sequence.value()));
  out += Line("slot_b",
              std::string(ToString(report.slot_b.status)) + " sequence=" +
                  std::to_string(report.slot_b.sequence.value()));
  for (const std::string& torn : report.torn_slots) {
    out += Line("torn", torn);
  }
  return out;
}

std::string RenderGenerations(const FacilityGenerations& generations, bool json) {
  if (json) {
    std::string out;
    JsonWriter writer(out);
    writer.BeginObject();
    writer.Field("facility_epoch", generations.facility_epoch.value());
    writer.Field("policy_generation", generations.policy_generation.value());
    writer.Field("dependency_generation", generations.dependency_generation.value());
    writer.Field("capacity_generation", generations.capacity_generation.value());
    writer.Field("topology_generation", generations.topology_generation.value());
    writer.Field("maintenance_generation", generations.maintenance_generation.value());
    writer.EndObject();
    out.push_back('\n');
    return out;
  }
  std::string out;
  out += "facility generations\n";
  out += Line("facility_epoch", std::to_string(generations.facility_epoch.value()));
  out += Line("policy_generation", std::to_string(generations.policy_generation.value()));
  out += Line("dependency_generation", std::to_string(generations.dependency_generation.value()));
  out += Line("capacity_generation", std::to_string(generations.capacity_generation.value()));
  out += Line("topology_generation", std::to_string(generations.topology_generation.value()));
  out += Line("maintenance_generation", std::to_string(generations.maintenance_generation.value()));
  return out;
}

}  // namespace decommissioning_fabric::cli
