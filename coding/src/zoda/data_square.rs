//! Data square with [`BinaryField`] elements

use super::BinaryField;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
};
use std::{borrow::Cow, fmt::Display, ops::Mul};

/// A matrix of [`BinaryField`] elements.
#[derive(Clone, Debug)]
pub struct DataSquare<'a, F: BinaryField> {
    data: Cow<'a, [F]>,
    rows: usize,
    cols: usize,
}

impl<'a, F: BinaryField> DataSquare<'a, F> {
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
        Self {
            data: Cow::Owned(data),
            rows,
            cols,
        }
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
        // SAFETY: all indicies passed to `row_iter` are in-bounds
        (0..self.rows).map(|row| unsafe { self.row_iter(row).unwrap_unchecked() })
    }

    /// Returns a parallel iterator over the rows of the data square.
    ///
    /// Each item in the outer iterator is a parallel iterator over the elements in that row.
    pub fn par_rows_iter(
        &self,
    ) -> impl IndexedParallelIterator<Item = impl IndexedParallelIterator<Item = &F>> {
        // SAFETY: all indicies passed to `row_par_iter` are in-bounds
        (0..self.rows)
            .into_par_iter()
            .map(|row| unsafe { self.row_par_iter(row).unwrap_unchecked() })
    }

    /// Returns a parallel iterator over the rows of the data square.
    ///
    /// Each item in the outer iterator is a standard iterator over the elements in that row.
    pub fn partial_par_rows_iter(
        &self,
    ) -> impl IndexedParallelIterator<Item = impl Iterator<Item = &F>> {
        // SAFETY: all indicies passed to `row_iter` are in-bounds
        (0..self.rows)
            .into_par_iter()
            .map(|row| unsafe { self.row_iter(row).unwrap_unchecked() })
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
        // SAFETY: all indicies passed to `col_iter` are in-bounds
        (0..self.cols).map(|row| unsafe { self.col_iter(row).unwrap_unchecked() })
    }

    /// Returns a parallel iterator over the columns of the data square.
    ///
    /// Each item in the outer iterator is a parallel iterator over the elements in that column.
    pub fn par_cols_iter(
        &self,
    ) -> impl IndexedParallelIterator<Item = impl IndexedParallelIterator<Item = &F>> {
        // SAFETY: all indicies passed to `col_par_iter` are in-bounds
        (0..self.cols)
            .into_par_iter()
            .map(|col| unsafe { self.col_par_iter(col).unwrap_unchecked() })
    }

    /// Returns a parallel iterator over the columns of the data square.
    ///
    /// Each item in the outer iterator is a standard iterator over the elements in that column.
    pub fn partial_par_cols_iter(
        &self,
    ) -> impl IndexedParallelIterator<Item = impl Iterator<Item = &F>> {
        // SAFETY: all indicies passed to `col_iter` are in-bounds
        (0..self.cols)
            .into_par_iter()
            .map(|col| unsafe { self.col_iter(col).unwrap_unchecked() })
    }

    /// Transposes the data square, returning a new `DataSquare` with rows and columns swapped.
    pub fn transpose(&self) -> Self {
        let (cols, rows) = (self.rows, self.cols);
        let data = self.cols_iter().flatten().copied().collect();
        Self { data, rows, cols }
    }
}

impl<'a, F, V> Mul<V> for &DataSquare<'a, F>
where
    F: BinaryField,
    V: AsRef<[F]>,
{
    type Output = Vec<F>;

    fn mul(self, rhs: V) -> Self::Output {
        let vector = rhs.as_ref();

        assert_eq!(vector.len(), self.cols, "Dimension mismatch");

        self.par_cols_iter()
            .zip(vector.par_iter())
            .map(|(col, scalar)| col.map(|elem| *elem * *scalar).collect::<Vec<F>>())
            .reduce_with(|col1, col2| col1.into_iter().zip(col2).map(|(e1, e2)| e1 + e2).collect())
            .expect("Iterator cannot be empty")
    }
}

impl<'a, F: BinaryField> Display for DataSquare<'a, F> {
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

#[cfg(test)]
mod test {
    use super::DataSquare;
    use crate::zoda::GF32;
    use rstest::rstest;

    #[inline]
    fn fields(dat: &[u32]) -> Vec<GF32> {
        dat.iter().copied().map(GF32::from).collect()
    }

    #[test]
    fn test_get() {
        let sq = DataSquare::new(fields(&[1, 2, 3, 4]), 2, 2);
        assert_eq!(sq.get(0, 0).unwrap(), &GF32::from(1));
        assert_eq!(sq.get(0, 1).unwrap(), &GF32::from(2));
        assert_eq!(sq.get(1, 0).unwrap(), &GF32::from(3));
        assert_eq!(sq.get(1, 1).unwrap(), &GF32::from(4));
    }

    #[test]
    fn test_row_iter() {
        let sq = DataSquare::new(fields(&[1, 2, 3, 4]), 2, 2);
        let row0: Vec<GF32> = sq.row_iter(0).unwrap().copied().collect();
        let row1: Vec<GF32> = sq.row_iter(1).unwrap().copied().collect();
        assert_eq!(row0, fields(&[1, 2]));
        assert_eq!(row1, fields(&[3, 4]));

        let rows = sq
            .rows_iter()
            .map(|i| i.copied().collect::<Vec<_>>())
            .collect::<Vec<_>>();
        assert_eq!(rows, vec![fields(&[1, 2]), fields(&[3, 4])]);
    }

    #[test]
    fn test_col_iter() {
        let sq = DataSquare::new(fields(&[1, 2, 3, 4]), 2, 2);
        let col0: Vec<GF32> = sq.col_iter(0).unwrap().copied().collect();
        let col1: Vec<GF32> = sq.col_iter(1).unwrap().copied().collect();
        assert_eq!(col0, fields(&[1, 3]));
        assert_eq!(col1, fields(&[2, 4]));

        let cols = sq
            .cols_iter()
            .map(|i| i.copied().collect::<Vec<_>>())
            .collect::<Vec<_>>();
        assert_eq!(cols, vec![fields(&[1, 3]), fields(&[2, 4])]);
    }

    #[test]
    fn test_transpose() {
        let sq = DataSquare::new(fields(&[1, 2, 3, 4]), 2, 2);
        let transposed = sq.transpose();
        assert_eq!(transposed.rows(), 2);
        assert_eq!(transposed.cols(), 2);
        assert_eq!(transposed.get(0, 0).unwrap(), &GF32::from(1));
        assert_eq!(transposed.get(0, 1).unwrap(), &GF32::from(3));
        assert_eq!(transposed.get(1, 0).unwrap(), &GF32::from(2));
        assert_eq!(transposed.get(1, 1).unwrap(), &GF32::from(4));
    }

    #[rstest]
    #[case(&[1, 2, 3, 4], &[5, 6], &[9, 23])]
    #[case(&[0xde, 0xad, 0xc0, 0xde], &[0xc0, 0x01], &[0x582D, 0x50DE])]
    #[should_panic(expected = "Dimension mismatch")]
    #[case(&[1, 2, 3, 4], &[0], &[])]
    fn test_multiply(#[case] mat: &[u32], #[case] vector: &[u32], #[case] expected: &[u32]) {
        assert!(mat.len() == 4, "Case only covers 2x2 matrices");

        let mat_dat = mat.iter().copied().map(GF32::from).collect::<Vec<_>>();
        let sq = DataSquare::new(mat_dat, 2, 2);

        let vector = vector.iter().copied().map(GF32::from).collect::<Vec<_>>();
        let expected = expected.iter().copied().map(GF32::from).collect::<Vec<_>>();

        assert_eq!(&sq * vector, expected);
    }
}
