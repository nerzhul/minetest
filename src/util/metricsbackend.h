/*
Minetest
Copyright (C) 2013-2020 Minetest core developers team

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation; either version 2.1 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#pragma once

#include <memory>
#include "cmake_config.h"
#include "irrlichttypes.h"
#if USE_PROMETHEUS
#include <prometheus/exposer.h>
#include <prometheus/registry.h>
#endif

class MetricCounter
{
public:
	MetricCounter() = default;

	virtual ~MetricCounter() {}

	virtual void increment(double number = 1.0) = 0;
	virtual double get() const = 0;
};

typedef std::shared_ptr<MetricCounter> MetricCounterPtr;

class SimpleMetricCounter : public MetricCounter
{
public:
	SimpleMetricCounter() = delete;

	virtual ~SimpleMetricCounter() {}

	SimpleMetricCounter(const std::string &name, const std::string &help_str) :
			MetricCounter(), m_name(name), m_help_str(help_str)
	{
	}

	virtual void increment(double number = 1.0) { m_counter += number; }
	virtual double get() const { return m_counter; }

private:
	std::string m_name;
	std::string m_help_str;

	double m_counter = 0.0;
};

class MetricGauge
{
public:
	MetricGauge() = default;
	virtual ~MetricGauge() {}

	virtual void increment(double number = 1.0) = 0;
	virtual void decrement(double number = 1.0) = 0;
	virtual void set(double number) = 0;
	virtual double get() const = 0;
};

typedef std::shared_ptr<MetricGauge> MetricGaugePtr;

class SimpleMetricGauge : public MetricGauge
{
public:
	SimpleMetricGauge() = delete;

	SimpleMetricGauge(const std::string &name, const std::string &help_str) :
			MetricGauge(), m_name(name), m_help_str(help_str)
	{
	}

	virtual ~SimpleMetricGauge() {}

	virtual void increment(double number = 1.0) { m_gauge += number; }
	virtual void decrement(double number = 1.0) { m_gauge -= number; }
	virtual void set(double number) { m_gauge = number; }
	virtual double get() const { return m_gauge; }

private:
	std::string m_name;
	std::string m_help_str;

	double m_gauge = 0.0;
};

class MetricsBackend
{
public:
	MetricsBackend() = default;

	virtual ~MetricsBackend() {}

	virtual MetricCounterPtr addCounter(
			const std::string &name, const std::string &help_str);
	virtual MetricGaugePtr addGauge(
			const std::string &name, const std::string &help_str);
};

#if USE_PROMETHEUS

class PrometheusMetricCounter : public MetricCounter
{
public:
	PrometheusMetricCounter() = delete;

	PrometheusMetricCounter(const std::string &name, const std::string &help_str,
			std::shared_ptr<prometheus::Registry> registry);

	virtual ~PrometheusMetricCounter() {}

	virtual void increment(double number = 1.0);
	virtual double get() const;

private:
	prometheus::Family<prometheus::Counter> &m_family;
	prometheus::Counter &m_counter;
};

class PrometheusMetricGauge : public MetricGauge
{
public:
	PrometheusMetricGauge() = delete;
	PrometheusMetricGauge(const std::string &name, const std::string &help_str,
			std::shared_ptr<prometheus::Registry> registry);

	virtual ~PrometheusMetricGauge() {}

	virtual void increment(double number = 1.0);
	virtual void decrement(double number = 1.0);
	virtual void set(double number);
	virtual double get() const;

private:
	prometheus::Family<prometheus::Gauge> &m_family;
	prometheus::Gauge &m_gauge;
};

class PrometheusMetricsBackend : public MetricsBackend
{
public:
	PrometheusMetricsBackend();

	virtual ~PrometheusMetricsBackend() {}

	virtual MetricCounterPtr addCounter(
			const std::string &name, const std::string &help_str);
	virtual MetricGaugePtr addGauge(
			const std::string &name, const std::string &help_str);

private:
	std::unique_ptr<prometheus::Exposer> m_exposer;
	std::shared_ptr<prometheus::Registry> m_registry;
};
#endif
