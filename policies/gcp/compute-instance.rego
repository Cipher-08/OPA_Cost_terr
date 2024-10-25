package main

# Define maximum hourly and monthly costs
max_hourly_cost = 1.00  # Adjust this to your spending limit
max_monthly_cost = 10.00  # Adjust this to your spending limit

# Loop through each project to check for violations
deny[msg] {
  project := input.projects[_]  # Iterating through each project

  # Extract the total costs from the project's breakdown
  hourly_cost := to_number(project.breakdown.totalHourlyCost)
  monthly_cost := to_number(project.breakdown.totalMonthlyCost)

  # Check if the costs exceed the limits
  hourly_cost > max_hourly_cost
  msg = sprintf("Project %v exceeds the hourly spending limit. Hourly cost: %v, Limit: %v", [project.name, hourly_cost, max_hourly_cost])
}

deny[msg] {
  project := input.projects[_]  # Iterating through each project

  # Extract the total costs from the project's breakdown
  hourly_cost := to_number(project.breakdown.totalHourlyCost)
  monthly_cost := to_number(project.breakdown.totalMonthlyCost)

  # Check if the costs exceed the limits
  monthly_cost > max_monthly_cost
  msg = sprintf("Project %v exceeds the monthly spending limit. Monthly cost: %v, Limit: %v", [project.name, monthly_cost, max_monthly_cost])
}
