//! Data square with [`BinaryField`] elements

use super::BinaryField;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
};
use std::{fmt::Display, ops::Mul};

/// A matrix of [`BinaryField`] elements.
#[derive(Clone, Debug)]
pub struct DataSquare<F: BinaryField> {
    pub data: Vec<F>,
    rows: usize,
    cols: usize,
}

impl<F: BinaryField> DataSquare<F> {
    /// Creates a new `DataSquare` from a flat vector of data and specified dimensions
    ///
    /// The data must be row-major; that is, the first `cols` elements of `data` will
    /// be the first row, the next `cols` elements will be the second row, and so on.
    pub fn new(data: Vec<F>, rows: usize, cols: usize) -> Self {
        assert_eq!(
            data.len(),
            rows * cols,
            "Data length does not match dimensions"
        );
        Self { data, rows, cols }
    }

    /// Returns the number of rows in the data square.
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Returns the number of columns in the data square.
    pub fn cols(&self) -> usize {
        self.cols
    }

    /// Gets a reference to the element at the specified row and column.
    pub fn get(&self, row: usize, col: usize) -> Option<&F> {
        (row < self.rows && col < self.cols).then(|| &self.data[row * self.cols + col])
    }

    /// Returns an iterator over the elements in a row of the data square.
    pub fn row_iter(&self, row: usize) -> Option<impl Iterator<Item = &F>> {
        (row < self.rows).then(|| {
            let start = row * self.cols;
            let end = start + self.cols;
            self.data[start..end].iter()
        })
    }

    /// Returns a parallel iterator over the elements in a row of the data square.
    pub fn row_par_iter(&self, row: usize) -> Option<impl IndexedParallelIterator<Item = &F>> {
        (row < self.rows).then(|| {
            let start = row * self.cols;
            let end = start + self.cols;
            self.data[start..end].par_iter()
        })
    }

    /// Returns an iterator over the rows of the data square.
    pub fn rows_iter(&self) -> impl Iterator<Item = impl Iterator<Item = &F>> {
        (0..self.rows).map(|row| self.row_iter(row).unwrap())
    }

    /// Returns a parallel iterator over the rows of the data square.
    ///
    /// Each item in the outer iterator is a parallel iterator over the elements in that row.
    pub fn par_rows_iter(
        &self,
    ) -> impl IndexedParallelIterator<Item = impl IndexedParallelIterator<Item = &F>> {
        (0..self.rows)
            .into_par_iter()
            .map(|row| self.row_par_iter(row).unwrap())
    }

    /// Returns a parallel iterator over the rows of the data square.
    ///
    /// Each item in the outer iterator is a standard iterator over the elements in that row.
    pub fn partial_par_rows_iter(
        &self,
    ) -> impl IndexedParallelIterator<Item = impl Iterator<Item = &F>> {
        (0..self.rows)
            .into_par_iter()
            .map(|row| self.row_iter(row).unwrap())
    }

    /// Returns an iterator over the elements in a column of the data square.
    pub fn col_iter(&self, col: usize) -> Option<impl Iterator<Item = &F>> {
        (col < self.cols).then(|| self.data.iter().skip(col).step_by(self.cols))
    }

    /// Returns a parallel iterator over the elements in a column of the data square.
    pub fn col_par_iter(&self, col: usize) -> Option<impl IndexedParallelIterator<Item = &F>> {
        (col < self.cols).then(|| self.data.par_iter().skip(col).step_by(self.cols))
    }

    /// Returns an iterator over the columns of the data square.
    pub fn cols_iter(&self) -> impl Iterator<Item = impl Iterator<Item = &F>> {
        (0..self.cols).map(|row| self.col_iter(row).unwrap())
    }

    /// Returns a parallel iterator over the columns of the data square.
    ///
    /// Each item in the outer iterator is a parallel iterator over the elements in that column.
    pub fn par_cols_iter(
        &self,
    ) -> impl IndexedParallelIterator<Item = impl IndexedParallelIterator<Item = &F>> {
        (0..self.cols)
            .into_par_iter()
            .map(|col| self.col_par_iter(col).unwrap())
    }

    /// Returns a parallel iterator over the columns of the data square.
    ///
    /// Each item in the outer iterator is a standard iterator over the elements in that column.
    pub fn partial_par_cols_iter(
        &self,
    ) -> impl IndexedParallelIterator<Item = impl Iterator<Item = &F>> {
        (0..self.cols)
            .into_par_iter()
            .map(|col| self.col_iter(col).unwrap())
    }

    /// Transposes the data square, returning a new `DataSquare` with rows and columns swapped.
    pub fn transpose(&self) -> Self {
        let (cols, rows) = (self.rows, self.cols);
        let data = self.cols_iter().flatten().copied().collect();
        Self { data, rows, cols }
    }
}

impl<F, V> Mul<V> for &DataSquare<F>
where
    F: BinaryField,
    V: AsRef<[F]>,
{
    type Output = Vec<F>;

    fn mul(self, rhs: V) -> Self::Output {
        let vector = rhs.as_ref();

        self.par_cols_iter()
            .zip(vector.par_iter())
            .map(|(col, scalar)| col.map(|elem| *elem * *scalar).collect::<Vec<F>>())
            .reduce_with(|col1, col2| col1.into_iter().zip(col2).map(|(e1, e2)| e1 + e2).collect())
            .expect("Iterator cannot be empty")
    }
}

impl<F: BinaryField> Display for DataSquare<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for row in 0..self.rows {
            for col in 0..self.cols {
                write!(f, "{} ", self.data[row * self.cols + col])?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}
