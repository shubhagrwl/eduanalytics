package util

import (
	"fmt"
	"time"
)

// ParseTime : func to parse various times in string format
func ParseTime(dateString string) (time.Time, error) {
	var parsedDate time.Time
	var err error
	parsedDate, err = time.Parse("2006-01-02T15:04:05.000Z", dateString)
	if err != nil {
		parsedDate, err = time.Parse("2006-01-02T15:04:05.000-07:00", dateString)
		if err != nil {
			parsedDate, err = time.Parse("2006-01-02T15:04:05Z", dateString)
			if err != nil {
				parsedDate, err = time.Parse("2006-01-02T15:04:05.9+02:00", dateString)
				if err != nil {
					parsedDate, err = time.Parse("2006-01-02T15:04:05.99+02:00", dateString)
					if err != nil {
						parsedDate, err = time.Parse("2006-01-02T15:04:05.999-07:00", dateString)
						if err != nil {
							parsedDate, err = time.Parse("2006-01-02T15:04:05.999999", dateString)
							if err != nil {
								parsedDate, err = time.Parse("2006-01-02T15:04:05-07:00", dateString)
								if err != nil {
									parsedDate, err = time.Parse("2006-01-02T15:04:05+07:00", dateString)
									if err != nil {
										parsedDate, err = time.Parse("2006-01-02 15:04:05.000+07", dateString)
										if err != nil {
											parsedDate, err = time.Parse("2006-01-02", dateString)
											if err != nil {
												parsedDate, err = time.Parse("2006-01-02 15:04:05.999999Z", dateString)
												if err != nil {
													parsedDate, err = time.Parse("2006-01-02 15:04:05.999999", dateString)
													if err != nil {
														parsedDate, err = time.Parse("2006/01/02", dateString)
														if err != nil {
															parsedDate, err = time.Parse("02/01/2006", dateString)
															if err != nil {
																return time.Time{}, err
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return parsedDate, nil
}

// ParseTime : func to parse various times in string format
func ParseTimeToISO(dateString string, locationString string) (string, error) {
	var parsedDate time.Time
	var err error
	loc, _ := time.LoadLocation(locationString)
	parsedDate, err = time.ParseInLocation("2006-01-02T03:04:05Z", dateString, loc)
	if err != nil {
		parsedDate, err = time.ParseInLocation("2006-01-02T03:04Z", dateString, loc)
		if err != nil {
			parsedDate, err = time.ParseInLocation("2006-01-02T3:04Z", dateString, loc)
			if err != nil {
				parsedDate, err = time.ParseInLocation("2006-01-02T15:04Z", dateString, loc)
				if err != nil {
					parsedDate, err = time.ParseInLocation("2006-01-02T15:04:05Z", dateString, loc)
					if err != nil {
						parsedDate, err = time.ParseInLocation("2006-01-02", dateString, loc)
						if err != nil {
							parsedDate, err = time.ParseInLocation("2006-01-02T15:04:05.000Z", dateString, loc)
							if err != nil {
								return "", err
							}
						}
					}
				}
			}
		}
	}
	return parsedDate.Format("2006-01-02T15:04:05-0700"), nil
}

func DateRange(week, month, year int) (startDate, endDate time.Time) {
	if week == 1 {
		startDate = time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC)
		// fmt.Println(startDate.Weekday())
		// fmt.Println(startDate.String())
		endDate = startDate
		// fmt.Println(endDate.String())
		// fmt.Println(endDate.Weekday())

	findWeekSaturday:
		if int(endDate.Weekday()) == int(time.Saturday) {
			return
		} else {
			endDate = endDate.AddDate(0, 0, 1)
			// fmt.Println(endDate.String())
			// fmt.Println(endDate.Weekday())

			goto findWeekSaturday
		}
	} else {
		timeBenchmark := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC)
		// fmt.Println(timeBenchmark.String())
		// fmt.Println(timeBenchmark.Weekday())
		// fmt.Println((timeBenchmark.Weekday() + 6) % 7)
		// fmt.Println(((timeBenchmark.Weekday() + 6) % 7).String())

		weekStartBenchmark := timeBenchmark.AddDate(0, 0, -(int(timeBenchmark.Weekday())+7)%7)
		// fmt.Println(weekStartBenchmark.String())
		// fmt.Println(weekStartBenchmark.Weekday())

		startDate = weekStartBenchmark.AddDate(0, 0, (week-1)*7)
		// fmt.Println(startDate.String())
		// fmt.Println(startDate.Weekday())

		endDate = startDate.AddDate(0, 0, 6)
		// fmt.Println(endDate.String())
		// fmt.Println(endDate.Weekday())
	}

	return
}

func DaysIn(m time.Month, year int) int {
	// This is equivalent to time.daysIn(m, year).
	return time.Date(year, m+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

type WeekWiseMonthDate struct {
	StartDate  string
	EndDate    string
	DaysInWeek int
}

func DaysInMonthWeekwise(m time.Month, year int) (dayWise map[int]WeekWiseMonthDate) {
	dayWise = make(map[int]WeekWiseMonthDate)
	// weekFirst := 1
	day := 1
	totalDays := 1
	daysInMonth := DaysIn(m, year)

	startDate := time.Date(year, m, day, 0, 0, 0, 0, time.UTC)
	_, weekFirst := startDate.ISOWeek()

	// dayWise[weekFirst] = WeekWiseMonthDate{
	// 	StartDate: startDate.Format("2006-01-02"),
	// }

	endDate := startDate

findLastSaturday:
	if endDate.Weekday() == time.Saturday {
		x := dayWise[weekFirst]
		x.DaysInWeek = day
		x.StartDate = startDate.Format("2006-01-02")
		x.EndDate = endDate.Format("2006-01-02")

		dayWise[weekFirst] = x

		if totalDays == daysInMonth {
			return
		} else {
			day = 0
			startDate = endDate.AddDate(0, 0, 1)
			weekFirst += 1
		}
	}

	if totalDays == daysInMonth {
		x := dayWise[weekFirst]
		x.DaysInWeek = day
		x.StartDate = startDate.Format("2006-01-02")
		x.EndDate = endDate.Format("2006-01-02")

		dayWise[weekFirst] = x
		return
	}

	endDate = endDate.AddDate(0, 0, 1)
	fmt.Println(endDate.String())
	totalDays += 1
	day += 1
	goto findLastSaturday
}
