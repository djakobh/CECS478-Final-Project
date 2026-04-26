#ifndef DNS_VALIDATOR_H
#define DNS_VALIDATOR_H

#include "../common.h"

/*
 * Validate that pkt looks like a legitimate DNS packet.
 * Returns a ValidationResult with is_valid=1 if it passes all checks,
 * or is_valid=0 with a reason string describing the first failure.
 */
ValidationResult dns_validate(const PacketFeatures *pkt);

#endif /* DNS_VALIDATOR_H */
