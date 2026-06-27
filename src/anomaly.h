#ifndef _STB_ANOMALY_H
#define _STB_ANOMALY_H

#include "../include/common.h"

/**
 * anomaly_detector - Detects network anomalies
 *
 * Monitors:
 * - Traffic spikes (sudden bandwidth increase)
 * - Port scanning (single source hitting many ports)
 * - Connection drops (RST storms)
 */
struct anomaly_detector;

struct anomaly_detector *anomaly_detector_create(void);
void anomaly_detector_destroy(struct anomaly_detector *ad);

/**
 * anomaly_check_flow - Check a flow event for anomalies
 *
 * @ad: Anomaly detector
 * @flow: Flow event to check
 *
 * Returns: ANOMALY_NONE, ANOMALY_SPIKE, ANOMALY_SCAN, or ANOMALY_DROP
 */
int anomaly_check_flow(struct anomaly_detector *ad, struct flow_event_t *flow);

/**
 * anomaly_detector_print_stats - Print detector statistics
 */
void anomaly_detector_print_stats(struct anomaly_detector *ad);

#endif
