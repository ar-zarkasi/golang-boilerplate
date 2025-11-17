package repository

import (
	"app/src/types"
	"strings"

	"gorm.io/gorm"
)

type BaseRepository[T any] interface {
	BaseQuery() *gorm.DB
	Create(item *T) error
	Update(id string, item *T) error
	Delete(id string) error
	GetListsCursor(filter []types.FilterQuery, lastValue string, lastColumn string, sort types.SORTING, limit int) ([]T, error)
}

type baseRepository[T any] struct {
	db       *gorm.DB
	model    T
	relation []string
}

func NewBaseRepository[T any](db *gorm.DB, model T, relationship []string) BaseRepository[T] {
	return &baseRepository[T]{db: db, model: model, relation: relationship}
}

func (r *baseRepository[T]) BaseQuery() *gorm.DB {
	base := r.db.Model(r.model)
	for _, rel := range r.relation {
		base = base.Preload(rel)
	}
	return base
}

func (r *baseRepository[T]) Create(item *T) error {
	if err := r.db.Create(&item).Error; err != nil {
		return err
	}
	return nil
}

func (r *baseRepository[T]) Update(id string, item *T) error {
	return r.db.Save(&item).Error
}

func (r *baseRepository[T]) Delete(id string) error {
	return r.db.Delete(r.model, "id = ?", id).Error
}

func (r *baseRepository[T]) GetListsCursor(filter []types.FilterQuery, lastValue string, lastColumn string, sort types.SORTING, limit int) ([]T, error) {
	var items []T
	query := r.BaseQuery()

	if len(filter) > 0 {
		for _, f := range filter {
			operandSmall := strings.ToLower(f.Operand)
			if len(f.ValueArray) > 0 {
				query = query.Where(f.Column+" IN ?", f.ValueArray)
			} else if operandSmall == "is_null" {
				query = query.Where(f.Column + " IS NULL")
			} else if operandSmall == "is_not_null" {
				query = query.Where(f.Column + " IS NOT NULL")
			} else if operandSmall == "in" {
				query = query.Where(f.Column+" IN ?", f.ValueArray)
			} else if operandSmall == "not_in" {
				query = query.Where(f.Column+" NOT IN ?", f.ValueArray)
			} else if operandSmall == "like" {
				query = query.Where(f.Column+" LIKE ?", "%"+*f.Value+"%")
			} else if operandSmall == "not_like" {
				query = query.Where(f.Column+" NOT LIKE ?", "%"+*f.Value+"%")
			} else if operandSmall == "between" && len(f.ValueArray) == 2 {
				query = query.Where(f.Column+" BETWEEN ? AND ?", f.ValueArray[0], f.ValueArray[1])
			} else if operandSmall == "not_between" && len(f.ValueArray) == 2 {
				query = query.Where(f.Column+" NOT BETWEEN ? AND ?", f.ValueArray[0], f.ValueArray[1])
			} else {
				query = query.Where(f.Column+" "+f.Operand+" ?", *f.Value)
			}
		}
	}

	if lastValue != "" && lastColumn != "" {
		if sort == types.SORTING_ASC {
			query = query.Where(lastColumn+" > ?", lastValue)
		} else {
			query = query.Where(lastColumn+" < ?", lastValue)
		}
	}
	if sort == types.SORTING_ASC {
		query = query.Order(lastColumn + " ASC")
	} else {
		query = query.Order(lastColumn + " DESC")
	}

	if err := query.Limit(limit).Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}
