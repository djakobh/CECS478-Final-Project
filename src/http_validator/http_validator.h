#ifndef HTTP_VALIDATOR_H
#define HTTP_VALIDATOR_H

#include "../common.h"

/*
 * Validate that pkt looks like a legitimate HTTP packet.
 * Returns a ValidationResult with is_valid=1 if it passes all checks,
 * or is_valid=0 with a reason string describing the first failure.
 */
ValidationResult http_validate(const PacketFeatures *pkt);

#endif /* HTTP_VALIDATOR_H */
