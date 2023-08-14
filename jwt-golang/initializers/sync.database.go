package initializers

import "jwt-golang/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.Users{})
}
