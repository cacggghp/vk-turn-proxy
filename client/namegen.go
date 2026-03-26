package main

import (
	"fmt"
	"math/rand"
)

// firstNames contains Russian first names. Add or remove names as needed.
var firstNames = []string{
	"Александр", "Дмитрий", "Максим", "Сергей", "Андрей", "Алексей", "Артём", "Илья",
	"Кирилл", "Михаил", "Никита", "Матвей", "Роман", "Егор", "Арсений", "Иван",
	"Денис", "Даниил", "Тимофей", "Владислав", "Игорь", "Павел", "Руслан", "Марк",
	"Анна", "Мария", "Елена", "Дарья", "Анастасия", "Екатерина", "Виктория", "Ольга",
	"Наталья", "Юлия", "Татьяна", "Светлана", "Ирина", "Ксения", "Алина", "Елизавета",
}

// lastNames contains Russian last names. Add or remove names as needed.
var lastNames = []string{
	"Иванов", "Смирнов", "Кузнецов", "Попов", "Васильев", "Петров", "Соколов", "Михайлов",
	"Новиков", "Федоров", "Морозов", "Волков", "Алексеев", "Лебедев", "Семенов", "Егоров",
	"Павлов", "Козлов", "Степанов", "Николаев", "Орлов", "Андреев", "Макаров", "Никитин",
	"Захаров", "Зайцев", "Соловьев", "Борисов", "Яковлев", "Григорьев", "Романов", "Воробьев",
}

// generateName generates a random Russian name.
// 30% chance to generate only first name, 70% chance first + last name.
// For female names (ending in 'а' or 'я'), adds 'а' to the last name.
func generateName() string {
	if rand.Float32() < 0.3 {
		return firstNames[rand.Intn(len(firstNames))]
	}

	fn := firstNames[rand.Intn(len(firstNames))]
	ln := lastNames[rand.Intn(len(lastNames))]

	// add 'a' to the last name for females
	lastChar := fn[len(fn)-2:] // 2 bytes for cyrillic
	if lastChar == "а" || lastChar == "я" {
		return fmt.Sprintf("%s %sа", fn, ln)
	}
	return fmt.Sprintf("%s %s", fn, ln)
}
